import {describe,expect,it} from 'vitest';
import {arbitrateIndependentLeef} from './independentLeefSource';
import {inspectIndependentQuotedCsv,arbitrateOptionalIndependentCsv,
  type CsvRecordContext} from './independentQuotedCsvSource';

const context:CsvRecordContext={recordFraming:'CONFIRMED_SINGLE_CSV_RECORD',
  treatUnquotedEmptyAsNull:true};
const original='test-001,2026-10-17,"alert, reviewed","A ""quoted"" event"';

describe('isolated vendor-neutral CSV source span review',()=>{
  it('does not infer CSV framing from unknown security logs',()=>{
    expect(inspectIndependentQuotedCsv(original).disposition).toBe('RAW_ONLY');
    expect(inspectIndependentQuotedCsv(original).positionalClaims).toEqual([]);
    expect(arbitrateOptionalIndependentCsv(original)).toEqual(arbitrateIndependentLeef(original));
  });
  it('decodes bounded RFC4180 quoted delimiter and doubled quote lexemes',()=>{
    const r=inspectIndependentQuotedCsv(original,context);
    expect(r.disposition).toBe('REVIEW_ONLY_POSITIONAL');
    expect(r.positionalClaims.map(c=>c.value)).toEqual([
      'test-001','2026-10-17','alert, reviewed','A "quoted" event']);
    expect(r.positionalClaims.map(c=>c.rawValueSpan)).toEqual([
      'test-001','2026-10-17','"alert, reviewed"','"A ""quoted"" event"']);
    for(const c of r.positionalClaims)
      expect(Buffer.from(original,'utf8').subarray(c.startByte,c.endByte).toString('utf8'))
        .toBe(c.rawValueSpan);
    expect(r.namedClaims).toEqual([]);
    expect(r.autoPromoted).toBe(false);
    expect(r.nativeVerified).toBe(false);
  });
  it('allows embedded line breaks only when independently single-record framed',()=>{
    const raw='2026-10-17,"multi\nline\r\nquoted",deny';
    const without=inspectIndependentQuotedCsv(raw);
    expect(without.disposition).toBe('RAW_ONLY');
    const framed=inspectIndependentQuotedCsv(raw,context);
    expect(framed.disposition).toBe('REVIEW_ONLY_POSITIONAL');
    expect(framed.positionalClaims.map(c=>c.value)).toEqual([
      '2026-10-17','multi\nline\r\nquoted','deny']);
    expect(framed.branchAttempts).toBeLessThanOrEqual(8);
  });
  it('distinguishes null, empty quoted string and one/two-column originals',()=>{
    const cases=[
      {raw:'',expected:null,disposition:'ABSTAIN_UNSAFE'},
      {raw:'src=192.0.2.1',expected:['src=192.0.2.1'],disposition:'REVIEW_ONLY_POSITIONAL'},
      {raw:'1,',expected:['1',null],disposition:'REVIEW_ONLY_POSITIONAL'},
      {raw:'1,""',expected:['1',''],disposition:'REVIEW_ONLY_POSITIONAL'},
      {raw:',,',expected:[null,null,null],disposition:'REVIEW_ONLY_POSITIONAL'},
    ] as const;
    for(const sample of cases){
      const r=inspectIndependentQuotedCsv(sample.raw,context);
      expect(r.disposition).toBe(sample.disposition);
      if(sample.expected)expect(r.positionalClaims.map(c=>c.value)).toEqual(sample.expected);
    }
  });
  it('checks original UTF-8 bytes rather than JS code-unit indices',()=>{
    const raw='2026,"\uC6D0\uBCF8 \uD0D0\uC9C0",success';
    const r=inspectIndependentQuotedCsv(raw,context);
    const value=r.positionalClaims[1]!;
    expect(value.value).toBe('\uC6D0\uBCF8 \uD0D0\uC9C0');
    expect(Buffer.from(raw,'utf8').subarray(value.startByte,value.endByte).toString('utf8'))
      .toBe(value.rawValueSpan);
    expect(value.startByte).toBe(Buffer.byteLength(raw.slice(0,raw.indexOf('"'))));
  });
  it('maps publisher-asserted header names from the original separate header record only',()=>{
    const headers='event_id,severity,details';
    const row='X-100,high,"Detected, blocked"';
    const r=inspectIndependentQuotedCsv(row,{...context,headerRaw:headers});
    expect(r.disposition).toBe('REVIEW_ONLY_NAMED');
    expect(r.namedClaims.map(c=>[c.name,c.value])).toEqual([
      ['event_id','X-100'],['severity','high'],['details','Detected, blocked']]);
    for(const c of r.namedClaims){
      expect(Buffer.from(row,'utf8').subarray(c.startByte,c.endByte).toString('utf8'))
        .toBe(c.rawValueSpan);
      const label=c.originalHeaderSpan;
      expect(Buffer.from(headers,'utf8').subarray(label.startByte,label.endByte)
        .toString('utf8')).toBe(label.rawValueSpan);
    }
    expect(r.independentOracleCertified).toBe(false);
  });
  it.each([
    'name,name,action',
    'src,Src,dst',
    'event,constructor,dst',
    'event,,dst',
    'event,no space,dst',
  ])('fails closed on duplicate or unqualified original source header %s',headerRaw=>{
    const r=inspectIndependentQuotedCsv('alpha,beta,gamma',{...context,headerRaw});
    expect(r.disposition).toBe('ABSTAIN_UNSAFE');
    expect(r.namedClaims).toHaveLength(0);
  });
  it.each([
    '2026,"truncated,quote',
    '2026,"quoted"text,fail',
    '2026,abc"def",fail',
    '2026,invalid\nrecord,fail',
    '2026,abc\u0000def,fail',
  ])('abstains without exposing partial source claims for malformed RFC4180 %s',raw=>{
    const r=inspectIndependentQuotedCsv(raw,context);
    expect(r.disposition).toBe('ABSTAIN_UNSAFE');
    expect(r.positionalClaims).toHaveLength(0);
    expect(r.namedClaims).toHaveLength(0);
    expect(r.raw).toBe(raw);
  });
  it('does not invent success from a positive self-asserted verdict or bypass a VETO',()=>{
    const positive=inspectIndependentQuotedCsv(original,context,{
      sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'});
    expect(positive.autoPromoted).toBe(false);
    expect(positive.independentOracleCertified).toBe(false);
    for(const veto of [
      {sourceIdentity:'MISMATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'CONFLICT'},
    ] as const){
      const r=inspectIndependentQuotedCsv(original,context,veto);
      expect(r.disposition).toBe('ABSTAIN_UNSAFE');
      expect(r.positionalClaims).toHaveLength(0);
      expect(r.autoPromoted).toBe(false);
    }
  });
  it('bounds payload bytes and original column count',()=>{
    const oversized=original+'x'.repeat(20000);
    expect(inspectIndependentQuotedCsv(oversized,context).disposition).toBe('ABSTAIN_UNSAFE');
    const columns=new Array(270).fill('v').join(',');
    expect(inspectIndependentQuotedCsv(columns,context).disposition).toBe('ABSTAIN_UNSAFE');
  });
  it('preserves the exact old path for CEF, LEEF, RFC syslog and JSON without CSV framing',()=>{
    for(const raw of [
      'CEF:0|Vendor|Device|1|A|Alarm|3|src=192.0.2.4 dst=203.0.113.8',
      'LEEF:1.0|Vendor|Device|1.0|E7|src=192.0.2.4\tdst=203.0.113.8',
      '<34>Oct 11 22:14:15 loghost daemon: code=allowed',
      '{"event":"blocked","severity":4}',
    ])expect(arbitrateOptionalIndependentCsv(raw)).toEqual(arbitrateIndependentLeef(raw));
  });
});
