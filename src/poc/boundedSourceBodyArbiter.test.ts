import {describe,expect,it} from 'vitest';
import {arbitrateSourceBody} from './boundedSourceBodyArbiter';
import {parseSecurityInput} from '../securityInputPipeline';

const utf8=(s:string)=>new TextEncoder().encode(s);
function replay(raw:string){
  const result=arbitrateSourceBody(raw);
  const bytes=utf8(raw);
  expect(result.raw).toBe(raw);
  expect(result.sourceBytes).toBe(bytes.length);
  expect(result.branchAttempts).toBeLessThanOrEqual(8);
  expect(result.maxBranchAttempts).toBe(8);
  expect(result.autoPromoted).toBe(false);
  expect(result.independentOracleCertified).toBe(false);
  expect(result.nativeVerified).toBe(false);
  for(const field of [...result.envelopeFields,...result.bodyClaims]){
    const slice=new TextDecoder('utf-8',{fatal:true}).decode(
      bytes.slice(field.startByte,field.endByte));
    expect(slice).toBe(field.rawSpanValue);
    if(field.evidence==='STANDARD_JSON_LITERAL')expect(JSON.parse(slice)).toEqual(field.value);
  }
  return result;
}

describe('Layered vendor-neutral source envelope and body arbitration',()=>{
  it('separates RFC3164 header evidence from exact named KV body fields',()=>{
    const raw='<14>Oct 17 13:14:15 firewall audit[2]: action=deny src=192.0.2.10 reason="policy check"';
    const result=replay(raw);
    expect(result.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(result.envelopeMode).toBe('rfc3164');
    expect(result.selectedBodyGrammar).toBe('kv_space');
    expect(result.envelopeFields.find(x=>x.name==='hostname')?.value).toBe('firewall');
    expect(result.bodyClaims.map(x=>[x.name,x.value])).toEqual([
      ['action','deny'],['src','192.0.2.10'],['reason','policy check'],
    ]);
    expect(result.candidateGrammars).toEqual(['kv_space']);
  });
  it('supports exact multibyte original-byte spans behind RFC5424 JSON MSG',()=>{
    const word='\uD55C\uAE00'+String.fromCodePoint(0x1f642);
    const raw='<33>1 2026-10-17T13:14:15Z host app - - - '+JSON.stringify({message:word,ok:true});
    const out=replay(raw);
    expect(out.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(out.envelopeMode).toBe('rfc5424');
    expect(out.bodyClaims.map(f=>f.path)).toEqual(['/body/message','/body/ok']);
    expect(out.bodyClaims[0]?.value).toBe(word);
    expect(out.bodyClaims[0]?.rawSpanValue).toBe(JSON.stringify(word));
  });
  it('preserves RFC5424 MSG internal LF and nested JSON field hierarchy',()=>{
    const raw='<10>1 2026-10-17T13:14:15Z host service - - - {\n  "payload": {"code":7},\n  "ok": true\n}';
    const out=replay(raw);
    expect(out.envelopeMode).toBe('rfc5424');
    expect(out.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(out.bodyClaims.map(f=>[f.path,f.value])).toEqual([
      ['/body/payload/code',7],['/body/ok',true],
    ]);
  });
  it('accepts standalone bounded JSON without inventing syslog header',()=>{
    const result=replay('{"a":7,"arr":[1,{"ok":false}]}');
    expect(result.disposition).toBe('REVIEW_ONLY_UNFRAMED');
    expect(result.envelopeFields).toEqual([]);
    expect(result.bodyClaims).toHaveLength(3);
  });
  it('preserves duplicate occurrences in a KV body instead of overwriting',()=>{
    const out=replay('<14>Oct 17 13:14:15 host app: user=a user=b state=deny');
    expect(out.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(out.bodyClaims.map(f=>f.path)).toEqual([
      '/body/kv/user#0','/body/kv/user#1','/body/kv/state#0',
    ]);
    expect(out.bodyClaims.map(f=>f.value)).toEqual(['a','b','deny']);
  });
  it('refuses malformed source envelope instead of parsing its attractive body',()=>{
    for(const input of [
      '<300>1 2026-10-17T13:14:15Z host app - - - action=allow src=1',
      '<1>1 2026-10-17T13:14:15Z host app - - [id key="bad]end"] a=1 b=2',
      '<1>1 2026-10-17T13:14:15Z host app - - - hello\n<2>1 2026-10-17T13:14:16Z host app - - - bye',
    ]){
      const out=replay(input);
      expect(out.disposition).toBe('ABSTAIN_UNSAFE');
      expect(out.bodyClaims).toEqual([]);
      expect(out.envelopeFields).toEqual([]);
    }
  });
  it('does not call a malformed escaped KV body source correct',()=>{
    const raw='<14>Oct 17 13:14:15 host app: foo="bad\\q" bar=clean';
    const out=replay(raw);
    expect(out.disposition).toBe('REVIEW_ONLY_ENVELOPE');
    expect(out.bodyClaims).toEqual([]);
    expect(out.reason).toBe('STRUCTURED_BODY_UNSCORABLE_WITHOUT_CONFIRMED_GRAMMAR');
  });
  it('leaves unknown CEF and free-form body unstructured without syntax shortcuts',()=>{
    const raw='<14>Oct 17 13:14:15 host CEF:0|Maker|Tool|1|e|alert|5|src=192.0.2.12';
    const out=replay(raw);
    expect(out.disposition).toBe('REVIEW_ONLY_ENVELOPE');
    expect(out.bodyClaims).toEqual([]);
  });
  it('retains original raw and refuses to promote upstream permissive malformed SD',()=>{
    const raw='<165>1 2003-10-11T22:14:15.003Z mymachine evntslog - ID47 [id key= "value"] test';
    const out=replay(raw);
    expect(out.disposition).toBe('ABSTAIN_UNSAFE');
    expect(out.autoPromoted).toBe(false);
  });
  it('never declares a syntactic body candidate a native parser success',()=>{
    for(const raw of [
      'src=192.0.2.1 dst=192.0.2.2 action=deny',
      'prefix src=192.0.2.1 dst=192.0.2.2',
      'src="ok" dst="done"',
    ]){
      const out=replay(raw);
      expect(out.autoPromoted).toBe(false);
      expect(out.independentOracleCertified).toBe(false);
      expect(out.nativeVerified).toBe(false);
    }
    expect(parseSecurityInput('src=192.0.2.1 dst=192.0.2.2 action=deny').ok).toBe(false);
  });
  it('only downgrades on qualified external evidence and never auto-promotes from a claimed PASS',()=>{
    const raw='<14>Oct 17 13:14:15 host app: src=192.0.2.1 dst=192.0.2.2';
    const baseline=replay(raw);
    expect(baseline.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    for(const review of [
      {sourceIdentity:'MISMATCH',structuralProfile:'UNSCORED',independentSourceTruth:'UNSCORED'},
      {sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'UNSCORED'},
      {sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'CONFLICT'},
    ] as const){
      const denied=arbitrateSourceBody(raw,review);
      expect(denied.disposition).toBe('ABSTAIN_UNSAFE');
      expect(denied.envelopeFields).toEqual([]);
      expect(denied.bodyClaims).toEqual([]);
      expect(denied.autoPromoted).toBe(false);
    }
    const claimed=arbitrateSourceBody(raw,{sourceIdentity:'MATCH',
      structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'});
    expect(claimed.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(claimed.autoPromoted).toBe(false);
    expect(claimed.independentOracleCertified).toBe(false);
    expect(claimed.nativeVerified).toBe(false);
  });
  it('is bounded for oversized input and rejects lossy JSON scalar interpretation',()=>{
    const tooLarge='{"msg":"'+('x'.repeat(66000))+'"}';
    expect(replay(tooLarge).disposition).toBe('ABSTAIN_UNSAFE');
    const unsafe='{"requestId":9007199254740993,"status":200}';
    expect(replay(unsafe).disposition).toBe('RAW_ONLY');
    expect(replay(unsafe).bodyClaims).toEqual([]);
  });
});
