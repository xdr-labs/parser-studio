import {describe,expect,it} from 'vitest';
import {arbitrateSourceBody} from './boundedSourceBodyArbiter';
import {arbitrateIndependentNonJson} from './independentNonJsonStructural';

const basic='CEF:0|Acme|Gateway|1.1|block|Denied access|5|src=10.0.0.1 dst=192.0.2.1';

describe('isolated independent non-JSON structural source observer',()=>{
  it('discovers producer-neutral CEF header and extension source spans',()=>{
    const result=arbitrateIndependentNonJson(basic);
    expect(result.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(result.raw).toBe(basic);
    expect(result.bodyClaims.map(f=>[f.name,f.value])).toEqual([
      ['version','0'],['deviceVendor','Acme'],['deviceProduct','Gateway'],
      ['deviceVersion','1.1'],['deviceEventClassId','block'],
      ['name','Denied access'],['severity','5'],['src','10.0.0.1'],['dst','192.0.2.1'],
    ]);
    const bytes=Buffer.from(basic,'utf8');
    for(const claim of result.bodyClaims){
      expect(bytes.subarray(claim.startByte,claim.endByte).toString('utf8')).toBe(claim.rawSpanValue);
      expect(claim.rawSpanValue).toBe(claim.value);
    }
    expect(result.branchAttempts).toBeLessThanOrEqual(8);
    expect(result.autoPromoted).toBe(false);
    expect(result.independentOracleCertified).toBe(false);
    expect(result.nativeVerified).toBe(false);
  });

  it('preserves UTF-8 byte ranges rather than character positions',()=>{
    const raw='CEF:0|\uBCF4\uC548|Router|1|E7|\uCC28\uB2E8 \uAE30\uB85D|3|src=10.0.0.1 dst=\uD14C\uC2A4\uD2B8';
    const result=arbitrateIndependentNonJson(raw);
    const source=Buffer.from(raw,'utf8');
    for(const claim of result.bodyClaims){
      expect(source.subarray(claim.startByte,claim.endByte).toString('utf8')).toBe(claim.value);
    }
    expect(result.bodyClaims.find(c=>c.name==='dst')?.value).toBe('\uD14C\uC2A4\uD2B8');
    expect(result.bodyClaims.find(c=>c.name==='name')?.startByte)
      .toBeGreaterThan(raw.indexOf('\uCC28\uB2E8 \uAE30\uB85D'));
  });

  it('separates an unverified timestamp/hostname prefix without inventing transport truth',()=>{
    const raw='Oct 12 04:16:11 localhost '+basic;
    const result=arbitrateIndependentNonJson(raw);
    expect(result.envelopeMode).toBe('unframed');
    expect(result.envelopeFields).toEqual([]);
    expect(result.bodyClaims.find(c=>c.name==='deviceVendor')?.value).toBe('Acme');
    expect(result.autoPromoted).toBe(false);
  });

  it.each([
    'CEF:Unknown|Acme|Gateway|1.1|block|Denied access|5|',
    'CEF:0|Acme|Gateway|1.1|',
    'CEF:0|Acme\\|Injected|Gateway|1.1|block|Denied access|5|',
    'Oct 12 04:16:11 localhost CEF:0|Acme|Gateway|1.1|',
    'CEF:0|Acme|Gateway|1.1|block|Denied access|5|src=x\u0000dst=y',
  ])('abstains on unqualified or incomplete CEF grammar: %s',raw=>{
    const result=arbitrateIndependentNonJson(raw);
    expect(result.disposition).toBe('ABSTAIN_UNSAFE');
    expect(result.bodyClaims).toEqual([]);
    expect(result.raw).toBe(raw);
  });

  it('avoids supplying speculative body claims when extension boundaries are unsafe',()=>{
    const raw='CEF:0|Acme|Gateway|1.1|block|Denied access|5|msg="open session user=abc"';
    const result=arbitrateIndependentNonJson(raw);
    expect(result.bodyClaims).toHaveLength(7);
    expect(result.disposition).toBe('REVIEW_ONLY_UNFRAMED');
    expect(result.selectedBodyGrammar).toBe('none');
    expect(result.bodyReviewEvidence).toBe('NOT_PROVEN');
    expect(result.autoPromoted).toBe(false);
  });

  it('keeps header and extension namespaces distinct and repeats source keys in order',()=>{
    const raw='CEF:0|Acme|Gateway|1|E|Blocked|3|name=extension name=repeated src=10.0.0.1';
    const claims=arbitrateIndependentNonJson(raw).bodyClaims;
    expect(claims.filter(c=>c.name==='name').map(c=>c.path)).toEqual([
      '/body/cef/header/name#0',
      '/body/cef/extension/name#0',
      '/body/cef/extension/name#1',
    ]);
    expect(claims.filter(c=>c.name==='name').map(c=>c.value)).toEqual([
      'Blocked','extension','repeated',
    ]);
    const blank='CEF:0|Acme|Gateway|1|E|Blocked|3|src= src=10.0.0.1 dst=192.0.2.1';
    const fields=arbitrateIndependentNonJson(blank).bodyClaims;
    expect(fields.find(c=>c.name==='src')?.path).toBe('/body/cef/extension/src#1');
  });

  it('keeps upstream bounded JSON and RFC Syslog cases byte-identical',()=>{
    for(const source of [
      '{"event":"hello","status":403}',
      '<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - ok',
      '<34>Oct 11 22:14:15 gateway app[10]: operation=blocked',
      'junk CEF:0|Acme|Gateway|1.1|block|Denied access|5|',
    ]){
      expect(arbitrateIndependentNonJson(source)).toEqual(arbitrateSourceBody(source));
    }
  });

  it('independent conflict or negative profile veto never exposes CEF claims',()=>{
    for(const veto of [
      {sourceIdentity:'MISMATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'CONFLICT'},
    ] as const){
      const result=arbitrateIndependentNonJson(basic,veto);
      expect(result.disposition).toBe('ABSTAIN_UNSAFE');
      expect(result.bodyClaims).toEqual([]);
      expect(result.independentOracleCertified).toBe(false);
      expect(result.autoPromoted).toBe(false);
    }
    const claimed=arbitrateIndependentNonJson(basic,{
      sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT',
    });
    expect(claimed.autoPromoted).toBe(false);
    expect(claimed.independentOracleCertified).toBe(false);
  });

  it('rejects excessive source bytes and keeps bounded branch count',()=>{
    const raw=basic+'x'.repeat(9000);
    const result=arbitrateIndependentNonJson(raw);
    expect(result.disposition).toBe('ABSTAIN_UNSAFE');
    expect(result.branchAttempts).toBeLessThanOrEqual(8);
    expect(result.autoPromoted).toBe(false);
  });
});
