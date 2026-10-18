import {describe,expect,it} from 'vitest';
import {extractStructuredFamily} from '../structuredFamilies';
import {scanCefStandardExtensions} from '../cefStandardExtensionGrammar';
import {arbitrateIndependentNonJson} from './independentNonJsonStructural';

const prefix='CEF:0|Vendor|Firewall|1.0|E1|Blocked traffic|5|';
const decoder=new TextDecoder('utf-8',{fatal:true});
const bytes=(raw:string)=>new TextEncoder().encode(raw);
const all=(suffix:string)=>prefix+suffix;
const sourceField=(raw:string,name:string)=>{
  const source=arbitrateIndependentNonJson(raw);
  return source.bodyClaims.find(x=>x.name===name&&x.path.includes('/extension/'));
};
const exactSource=(raw:string)=>{
  const source=arbitrateIndependentNonJson(raw);
  const wire=bytes(raw);
  for(const claim of source.bodyClaims)
    expect(decoder.decode(wire.subarray(claim.startByte,claim.endByte)))
      .toBe(claim.rawSpanValue);
  expect(source.nativeVerified).toBe(false);
  expect(source.autoPromoted).toBe(false);
  return source;
};

describe('P0-STD-3 CEF generic extension escape, whitespace, offset and abstention',()=>{
  it('retains spaces and unescaped pipes inside extension values',()=>{
    const raw=all('src=192.0.2.1 msg=blocked a | dst=198.51.100.1');
    const b=extractStructuredFamily(raw,'cef');
    expect(b.errors).toEqual([]);
    expect(b.fields.msg).toBe('blocked a |');
    const source=exactSource(raw);
    expect(source.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(sourceField(raw,'msg')).toMatchObject({
      name:'msg',value:'blocked a |',rawSpanValue:'blocked a |',
    });
  });

  it('decodes escaped equals and backslash without changing source lexemes',()=>{
    const raw=all('src=192.0.2.1 eq=a\\=b path=root\\\\folder');
    const b=extractStructuredFamily(raw,'cef');
    expect(b.errors).toEqual([]);
    expect(b.fields.eq).toBe('a=b');
    expect(b.fields.path).toBe('root\\folder');
    const s=exactSource(raw);
    expect(s.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(sourceField(raw,'eq')).toMatchObject({value:'a=b',rawSpanValue:'a\\=b'});
    expect(sourceField(raw,'path')).toMatchObject({
      value:'root\\folder',rawSpanValue:'root\\\\folder',
    });
  });

  it('decodes CEF escaped newline only in extension, never physical framing',()=>{
    const raw=all('msg=First\\n Second src=192.0.2.1');
    const b=extractStructuredFamily(raw,'cef');
    expect(b.errors).toEqual([]);
    expect(b.fields.msg).toBe('First\n Second');
    expect(sourceField(raw,'msg')).toMatchObject({
      value:'First\n Second',rawSpanValue:'First\\n Second',
    });
    expect(exactSource(raw).disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(extractStructuredFamily(all('msg=First\n Second src=1'),'cef').errors.length)
      .toBeGreaterThan(0);
  });

  it('keeps original UTF-8 offsets after non-ASCII header and values',()=>{
    const raw='CEF:0|\uBCF4\uC548|Firewall|1|E2|\uCC28\uB2E8 \uD65C\uB3D9|5|user=\uD55C\uAE00😀 msg=\uBB38\uC81C \uD5C8\uC6A9';
    const parsed=extractStructuredFamily(raw,'cef');
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.user).toBe('\uD55C\uAE00😀');
    expect(parsed.fields.msg).toBe('\uBB38\uC81C \uD5C8\uC6A9');
    const observed=exactSource(raw);
    expect(observed.bodyClaims.find(x=>x.name==='user')?.startByte)
      .toBeGreaterThan(raw.indexOf('user='));
    expect(observed.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
  });

  it('retains unknown producer escapes literally, never applying KV semantics',()=>{
    const raw=all('msg=odd\\qsource act=deny');
    const b=extractStructuredFamily(raw,'cef');
    expect(b.errors).toEqual([]);
    expect(b.fields.msg).toBe('odd\\qsource');
    expect(sourceField(raw,'msg')).toMatchObject({
      rawSpanValue:'odd\\qsource',value:'odd\\qsource',
    });
    expect(exactSource(raw).disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
  });

  it('tracks trailing spaces before next key but trims final decoded CEF spaces',()=>{
    const raw=all('act=blocked   src=192.0.2.1 ');
    const b=extractStructuredFamily(raw,'cef');
    expect(b.errors).toEqual([]);
    expect(b.fields.act).toBe('blocked  ');
    expect(b.fields.src).toBe('192.0.2.1');
    const source=exactSource(raw);
    expect(source.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(sourceField(raw,'act')).toMatchObject({
      rawSpanValue:'blocked  ',value:'blocked  ',
    });
    expect(sourceField(raw,'src')).toMatchObject({
      rawSpanValue:'192.0.2.1 ',value:'192.0.2.1',
    });
  });

  it('preserves ordered repeated source keys for review; browser fails closed',()=>{
    const raw=all('msg=first msg=second src=192.0.2.1');
    const browser=extractStructuredFamily(raw,'cef');
    expect(browser.errors.length).toBeGreaterThan(0);
    expect(browser.fields).toEqual({});
    const source=exactSource(raw);
    expect(source.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    const claims=source.bodyClaims.filter(c=>c.name==='msg');
    expect(claims.map(c=>c.path)).toEqual([
      '/body/cef/extension/msg#0','/body/cef/extension/msg#1',
    ]);
    expect(claims.map(c=>c.value)).toEqual(['first','second']);
  });

  it('does not guess empty field semantics from a duplicate or adjacent key',()=>{
    const raw=all('src= dst=192.0.2.1');
    const browser=extractStructuredFamily(raw,'cef');
    expect(browser.errors).toEqual([]);
    expect(browser.fields.src).toBe('');
    const source=exactSource(raw);
    expect(source.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(source.bodyClaims.filter(c=>c.name==='src')).toHaveLength(0);
    expect(source.bodyClaims.filter(c=>c.name==='dst')).toHaveLength(1);
  });

  it('abstains when quote-looking text contains a speculative source key boundary',()=>{
    const raw=all('msg="open session user=abc"');
    const browser=extractStructuredFamily(raw,'cef');
    expect(browser.errors.length).toBeGreaterThan(0);
    const source=arbitrateIndependentNonJson(raw);
    expect(source.disposition).toBe('REVIEW_ONLY_UNFRAMED');
    expect(source.bodyClaims).toHaveLength(7);
    expect(source.bodyReviewEvidence).toBe('NOT_PROVEN');
  });

  it('rejects truncated escape, unsafe keys and unaccounted original control bytes',()=>{
    for(const ext of ['msg=truncated\\', '__proto__=bad src=1',
      'msg=bad\u0001wire src=1', 'broken token without key']){
      const scanned=scanCefStandardExtensions(ext);
      expect(scanned.ok).toBe(false);
      const browser=extractStructuredFamily(all(ext),'cef');
      expect(browser.errors.length).toBeGreaterThan(0);
      const source=arbitrateIndependentNonJson(all(ext));
      expect(source.disposition).not.toBe('REVIEW_ONLY_STRUCTURED_BODY');
    }
  });

  it('bounds field scans and source byte ranges without native promotion',()=>{
    expect(scanCefStandardExtensions('src=x'.repeat(18000)).ok).toBe(false);
    const raw=all('src=192.0.2.1 act=allow');
    const beginning=raw.indexOf('src=');
    const scanned=scanCefStandardExtensions(raw,beginning);
    expect(scanned.ok).toBe(true);
    if(scanned.ok){
      expect(scanned.fields).toHaveLength(2);
      expect(scanned.fields[0]?.valueStartByte)
        .toBe(bytes(raw.slice(0,beginning+'src='.length)).length);
      for(const field of scanned.fields)
        expect(decoder.decode(bytes(raw).subarray(
          field.valueStartByte,field.valueEndByte))).toBe(field.rawValueLexeme);
    }
  });
});
