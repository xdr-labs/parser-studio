import {describe,expect,it} from 'vitest';
import {arbitrateOptionalIndependentCsv} from './independentQuotedCsvSource';
import {arbitrateOptionalIndependentLogfmt,inspectIndependentLogfmt,
  type LogfmtContext} from './independentLogfmtSource';

// Deliberately synthetic developer-created records; sealed publisher originals
// and their independently asserted field/value goldens never enter Git.
const single:LogfmtContext={recordFraming:'CONFIRMED_LOGFMT_SINGLE_RECORD'};
const batch:LogfmtContext={recordFraming:'CONFIRMED_LOGFMT_BATCH_RECORDS'};
const sample='operation=deny host=router-19 bytes=1294';

describe('isolated, producer-neutral logfmt source byte evidence',()=>{
  it('never sniffs unknown events or changes the previous source observer',()=>{
    expect(inspectIndependentLogfmt(sample).disposition).toBe('RAW_ONLY');
    expect(inspectIndependentLogfmt(sample).claims).toEqual([]);
    for(const raw of [
      sample,'{"code":200}','LEEF:1.0|Vendor|Device|1|E7|src=192.0.2.1',
      'CEF:0|Vendor|Device|1|E7|Alert|5|src=192.0.2.1 dst=203.0.113.1',
      '<34>Oct 11 22:14:15 gateway process[4]: src=192.0.2.1',
    ])expect(arbitrateOptionalIndependentLogfmt(raw))
      .toEqual(arbitrateOptionalIndependentCsv(raw));
  });

  it('keeps source field names, values, occurrence paths and original byte spans',()=>{
    const observed=inspectIndependentLogfmt(sample,single);
    expect(observed.disposition).toBe('REVIEW_ONLY_LOGFMT_LEXICAL');
    expect(observed.claims.map(c=>[c.name,c.value])).toEqual([
      ['operation','deny'],['host','router-19'],['bytes','1294'],
    ]);
    const raw=Buffer.from(sample,'utf8');
    for(const field of observed.claims)
      expect(raw.subarray(field.startByte,field.endByte).toString('utf8'))
        .toBe(field.rawValueSpan);
    expect(observed.autoPromoted).toBe(false);
    expect(observed.independentOracleCertified).toBe(false);
    expect(observed.nativeVerified).toBe(false);
    expect(observed.branchAttempts).toBeLessThanOrEqual(8);
  });

  it('decodes only standard, replayable quoted escapes with exact byte boundaries',()=>{
    const raw='action="one\\ttwo" message="first\\nsecond" raw="a\\\\b"';
    const result=inspectIndependentLogfmt(raw,single);
    expect(result.disposition).toBe('REVIEW_ONLY_LOGFMT_LEXICAL');
    expect(result.claims.map(c=>c.value)).toEqual([
      'one\ttwo','first\nsecond','a\\b',
    ]);
    const bytes=Buffer.from(raw,'utf8');
    for(const claim of result.claims)
      expect(bytes.subarray(claim.startByte,claim.endByte).toString('utf8'))
        .toBe(claim.rawValueSpan);
    expect(result.claims[0]?.rawValueSpan).toBe('"one\\ttwo"');
  });

  it('keeps Unicode source key names and UTF-8 byte spans',()=>{
    const raw='\u0192=2h3s label="\uC6D0\uBCF8 \uBCF4\uC874"';
    const r=inspectIndependentLogfmt(raw,single);
    expect(r.claims.map(c=>[c.name,c.value])).toEqual([
      ['\u0192','2h3s'],['label','\uC6D0\uBCF8 \uBCF4\uC874'],
    ]);
    const original=Buffer.from(raw,'utf8');
    for(const claim of r.claims)
      expect(original.subarray(claim.startByte,claim.endByte).toString('utf8'))
        .toBe(claim.rawValueSpan);
  });

  it('separates repeated keys across original-record byte boundaries',()=>{
    const raw='x=one x=two\ny=three x=four';
    expect(inspectIndependentLogfmt(raw,single).disposition).toBe('ABSTAIN_UNSAFE');
    const result=inspectIndependentLogfmt(raw,batch);
    expect(result.disposition).toBe('REVIEW_ONLY_PARTIAL');
    expect(result.claims.map(c=>[c.name,c.value,c.recordIndex,c.occurrence])).toEqual([
      ['x','one',0,0],['x','two',0,1],
      ['y','three',1,0],['x','four',1,0],
    ]);
    expect(result.claims.map(c=>c.path)).toEqual([
      '/body/logfmt/record0/x#0','/body/logfmt/record0/x#1',
      '/body/logfmt/record1/y#0','/body/logfmt/record1/x#0',
    ]);
  });

  it('handles explicit record separator and CRLF without merging records',()=>{
    const raw='src=192.0.2.1  \r\n\x1edst=198.51.100.10';
    const r=inspectIndependentLogfmt(raw,batch);
    expect(r.recordsSeen).toBe(2);
    expect(r.claims.map(c=>[c.name,c.recordIndex])).toEqual([
      ['src',0],['dst',1],
    ]);
  });

  it('keeps adjacent assignments review-only rather than claiming full coverage',()=>{
    const raw='code="hello\\n"host=192.0.2.1';
    const r=inspectIndependentLogfmt(raw,single);
    expect(r.disposition).toBe('REVIEW_ONLY_PARTIAL');
    expect(r.claims.map(c=>c.value)).toEqual(['hello\n','192.0.2.1']);
    expect(r.autoPromoted).toBe(false);
  });

  it('does not guess the meaning of unquoted empty or bare source values',()=>{
    const raw='type=alarm missing blank= device=router';
    const r=inspectIndependentLogfmt(raw,single);
    expect(r.disposition).toBe('REVIEW_ONLY_PARTIAL');
    expect(r.unsourcedBareKeys).toBe(2);
    expect(r.claims.map(c=>[c.name,c.value])).toEqual([
      ['type','alarm'],['device','router'],
    ]);
    expect(inspectIndependentLogfmt('empty= bare',single).claims).toEqual([]);
    const quoted=inspectIndependentLogfmt('empty="" device=router',single);
    expect(quoted.claims.find(c=>c.name==='empty')?.value).toBe('');
    expect(quoted.claims.find(c=>c.name==='empty')?.rawValueSpan).toBe('""');
  });

  it.each([
    'src="unterminated',
    'src="unsupported\\q" dst=192.0.2.1',
    'src="invalid"junk dst=192.0.2.1',
    'constructor=unsafe dst=192.0.2.1',
    'src=192.0.2.1\u0000dst=198.51.100.1',
    'src=192.0.2.1\uD800',
    '=bad dst=192.0.2.1',
  ])('abstains without leaking partial claims on unsafe logfmt originals: %s',raw=>{
    const result=inspectIndependentLogfmt(raw,single);
    expect(result.disposition).toBe('ABSTAIN_UNSAFE');
    expect(result.claims).toEqual([]);
    expect(result.raw).toBe(raw);
    expect(result.autoPromoted).toBe(false);
  });

  it('prevents independent profile VETO from being overridden by accepted syntax',()=>{
    for(const review of [
      {sourceIdentity:'MISMATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'CONFLICT'},
    ] as const){
      const r=inspectIndependentLogfmt(sample,single,review);
      expect(r.disposition).toBe('ABSTAIN_UNSAFE');
      expect(r.claims).toEqual([]);
      expect(r.nativeVerified).toBe(false);
    }
    const claimed=inspectIndependentLogfmt(sample,single,{
      sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'});
    expect(claimed.autoPromoted).toBe(false);
    expect(claimed.independentOracleCertified).toBe(false);
  });

  it('bounds input bytes, records, and source claims',()=>{
    const large=sample+'x'.repeat(17000);
    expect(inspectIndependentLogfmt(large,single).disposition).toBe('ABSTAIN_UNSAFE');
    const limit=new Array(64).fill('code=denied').join('\n')+'\n';
    const atLimit=inspectIndependentLogfmt(limit,batch);
    expect(atLimit.recordsSeen).toBe(64);
    expect(atLimit.disposition).toBe('REVIEW_ONLY_PARTIAL');
    const overLimit=new Array(65).fill('code=denied').join('\n');
    expect(inspectIndependentLogfmt(overLimit,batch).disposition).toBe('ABSTAIN_UNSAFE');
    const tooManyFields=new Array(260).fill('code=denied').join(' ');
    expect(inspectIndependentLogfmt(tooManyFields,single).disposition).toBe('ABSTAIN_UNSAFE');
  });
});
