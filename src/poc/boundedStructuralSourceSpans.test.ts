import {describe,expect,it} from 'vitest';
import {inspectBoundedSourceSpans} from './boundedStructuralSourceSpans';
import {parseSecurityInput} from '../securityInputPipeline';

const bytes=(s:string)=>new TextEncoder().encode(s);
function assertOriginalSourceByteSpans(raw:string,labels:Array<[string,string]>) {
  const candidate=inspectBoundedSourceSpans(raw);
  expect(candidate.disposition).toBe('REVIEW_ONLY');
  expect(candidate.autoPromoted).toBe(false);
  expect(candidate.nativeVerified).toBe(false);
  const original=bytes(raw);
  for(const [path,expectedToken] of labels){
    const found=candidate.fields.find(f=>f.path===path);
    expect(found).toBeDefined();
    const roundTrip=new TextDecoder('utf-8',{fatal:true}).decode(
      original.slice(found!.startByte,found!.endByte));
    expect(roundTrip).toBe(expectedToken);
  }
  return candidate;
}
describe('bounded, vendor-agnostic JSON source-span candidate',()=>{
  it('anchors exact UTF-8 multibyte source tokens including emoji and escaping',()=>{
    const raw='{"name":"\uD55C\uAE00🙂","escaped":"a\\\"b","items":[{"ok":true},3,null],"unit":"é"}';
    const output=assertOriginalSourceByteSpans(raw,[
      ['/name','"\uD55C\uAE00🙂"'],['/escaped','"a\\\"b"'],
      ['/items/0/ok','true'],['/items/1','3'],['/items/2','null'],['/unit','"é"'],
    ]);
    expect(output.fields).toHaveLength(6);
    expect(output.bodyStartByte).toBe(0);
    expect(output.maxDepthObserved).toBeLessThanOrEqual(5);
  });
  it('provides full-source byte offsets after RFC3164 framing',()=>{
    const prefix='<14>Oct 17 12:34:56 host worker[19]: ';
    const raw=prefix+'{"phase":"\uAC80\uC99D","alerts":[{"code":"ID"}]}';
    const output=assertOriginalSourceByteSpans(raw,[
      ['/phase','"\uAC80\uC99D"'],['/alerts/0/code','"ID"'],
    ]);
    expect(output.syntax).toBe('syslog_json_object');
    expect(output.bodyStartByte).toBe(bytes(prefix).length);
  });
  it('handles structured RFC5424 envelope with validated source boundary',()=>{
    const prefix='<134>1 2026-10-17T12:34:56Z fw01 appsrv - ID47 - ';
    const raw=prefix+'{"fields":{"decision":"allow","unicode":"\uC11C\uC6B8"}}';
    const output=assertOriginalSourceByteSpans(raw,[
      ['/fields/decision','"allow"'],['/fields/unicode','"\uC11C\uC6B8"'],
    ]);
    expect(output.bodyStartByte).toBe(bytes(prefix).length);
  });
  it('abstains on duplicate keys and escaped aliases, not source overwrite',()=>{
    for(const raw of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}']){
      const output=inspectBoundedSourceSpans(raw);
      expect(output.disposition).toBe('ABSTAIN_UNSAFE');
      expect(output.cause).toBe('DUPLICATE_OR_UNSAFE_JSON_KEY');
      expect(output.fields).toEqual([]);
      expect(output.autoPromoted).toBe(false);
    }
    // The shared RFC8259 source gate now rejects the prior silent overwrite.
    // This is a changed safety policy, not new manufacturer field accuracy.
    expect(parseSecurityInput('{"a":1,"a":2}').ok).toBe(false);
  });
  it('abstains on unsafe integer, instead of silently rounding the source',()=>{
    const raw='{"event_id":9007199254740993,"user":{"id":7}}';
    const output=inspectBoundedSourceSpans(raw);
    expect(output.disposition).toBe('ABSTAIN_UNSAFE');
    expect(output.cause).toBe('LOSSY_JSON_INTEGER_NEEDS_REVIEW');
    expect(output.fields).toEqual([]);
    // JavaScript Number would silently round the source integer.
    expect(parseSecurityInput(raw).ok).toBe(false);
  });
  it('rejects malformed UTF-8 conceptual content, numeric overflow and JSON string',()=>{
    for(const raw of [
      '{"x":"\\ud800"}', '{"x":1e999}', '{"x":"never closed}',
      '{"x":1 trailing}', '{"x":false,}', '{"x": "\\q"}',
    ]){
      const output=inspectBoundedSourceSpans(raw);
      expect(output.disposition).not.toBe('REVIEW_ONLY');
      expect(output.fields).toEqual([]);
      expect(output.autoPromoted).toBe(false);
    }
  });
  it('never upgrades a grammar match or an ambiguous envelope to a full success',()=>{
    for(const raw of [
      'src=192.0.2.1 dst=198.51.100.4 action=blocked',
      '<999>Oct 17 12:34:56 host {"x":1}',
      'CEF:0|Vendor|Product|1|alert|alert|3|src=192.0.2.1',
      '{"payload": "ok"} trailing garbage',
      '',
    ]){
      const result=inspectBoundedSourceSpans(raw);
      expect(result.disposition).not.toBe('REVIEW_ONLY');
      expect(result.autoPromoted).toBe(false);
      expect(result.fields).toHaveLength(0);
    }
  });
  it('bounds source bytes, field count and nesting without recursion explosion',()=>{
    const huge='{"msg":"'+('x'.repeat(65536))+'"}';
    const over=inspectBoundedSourceSpans(huge);
    expect(over.disposition).toBe('RAW_ONLY');
    let deep='0';
    for(let i=0;i<25;i++)deep='['+deep+']';
    const nested=inspectBoundedSourceSpans('{"children":'+deep+'}');
    expect(nested.disposition).toBe('ABSTAIN_UNSAFE');
    expect(nested.cause).toBe('BOUNDED_PARSE_EXHAUSTED');
  });
  it('does not invent a source field for anonymous or invalid JSON records',()=>{
    for(const raw of ['[]','[{"x":1}]','{}','{"nested":{}}']){
      const out=inspectBoundedSourceSpans(raw);
      expect(out.autoPromoted).toBe(false);
      expect(out.fields).toHaveLength(0);
    }
  });
});
