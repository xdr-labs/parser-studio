import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,it,expect} from 'vitest';
import {readCsvSourceCells} from '../csvSourceCells';
import {
  inspectIndependentQuotedCsv,arbitrateOptionalIndependentCsv,
} from './independentQuotedCsvSource';

type Cell={
  ordinal:number;name:string;value:string;quoted:boolean;bracedGroup:boolean;
  startByte:number;endByte:number;rawLexeme:string;
};
type Case={
  id:string;wire:string;declaredColumns:number[];headerRaw:string;
  valid:boolean;sourceBytes:number;sha256:string;cells:Cell[];
};
const pin=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standard83DeclaredBracedCsv.pinned.json'));
const pinnedSha='c1f149a7e831c99bf25e68c9d5c82bf72ef07ffc1cedf5b9c9033d3fc6eb1027';
const sha=(b:Uint8Array)=>createHash('sha256').update(b).digest('hex');
if(sha(pin)!==pinnedSha)throw Error('Independent declared braced CSV source oracle SHA changed');
const cases=(JSON.parse(pin.toString('utf8')) as {cases:Case[]}).cases;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf8',{fatal:true,ignoreBOM:true});
const context=(t:Case)=>({
  recordFraming:'CONFIRMED_SINGLE_CSV_RECORD' as const,
  headerRaw:t.headerRaw,
  declaredBracedGroupColumns:t.declaredColumns,
});

describe('P0-STD-83 explicit braced-field non-RFC4180 CSV dialect',()=>{
  it('freezes independent hand-authored raw, value and byte-boundary denominators',()=>{
    expect(cases).toHaveLength(33);
    expect(cases.filter(c=>c.valid)).toHaveLength(14);
    expect(cases.filter(c=>!c.valid)).toHaveLength(19);
    expect(cases.flatMap(c=>c.cells)).toHaveLength(54);
    expect(cases.filter(c=>c.valid)
      .flatMap(c=>c.cells).filter(x=>x.bracedGroup).length).toBeGreaterThan(9);
  });

  it.each(cases)('never automatically treats arbitrary braces as qualified CSV: $id',t=>{
    const raw=encoder.encode(t.wire);
    expect(sha(raw)).toBe(t.sha256);
    expect(raw.length).toBe(t.sourceBytes);
    const inspected=inspectIndependentQuotedCsv(t.wire,context(t));
    expect(inspected.raw).toBe(t.wire);
    expect(inspected.sourceBytes).toBe(raw.length);
    expect(inspected.autoPromoted).toBe(false);
    expect(inspected.independentOracleCertified).toBe(false);
    expect(inspected.nativeVerified).toBe(false);
    expect(inspected.branchAttempts).toBeLessThanOrEqual(8);
    if(!t.valid){
      expect(inspected.disposition).toBe('ABSTAIN_UNSAFE');
      expect(inspected.positionalClaims).toEqual([]);
      expect(inspected.namedClaims).toEqual([]);
      return;
    }
    expect(inspected.disposition).toBe('REVIEW_ONLY_NAMED');
    expect(inspected.reviewEvidence).toBe(
      'EXPLICIT_FRAMING_DECLARED_BRACED_GROUP_DIALECT');
    expect(inspected.positionalClaims).toHaveLength(t.cells.length);
    expect(inspected.namedClaims).toHaveLength(t.cells.length);
    for(const expected of t.cells){
      const c=inspected.namedClaims[expected.ordinal]!;
      expect({
        ordinal:c.ordinal,name:c.name,value:c.value,
        startByte:c.startByte,endByte:c.endByte,
        rawValueSpan:c.rawValueSpan,
      }).toEqual({
        ordinal:expected.ordinal,name:expected.name,value:expected.value,
        startByte:expected.startByte,endByte:expected.endByte,
        rawValueSpan:expected.rawLexeme,
      });
      expect(decoder.decode(raw.subarray(c.startByte,c.endByte)))
        .toBe(expected.rawLexeme);
      expect(c.evidence).toBe(expected.bracedGroup?
        'BOUNDED_SOURCE_BYTE_AND_DECLARED_BRACED_GROUP':
        'BOUNDED_SOURCE_BYTE_AND_RFC4180_DECODE');
      const cells=readCsvSourceCells(t.wire,',',false,{
        declaredBracedGroupColumns:t.declaredColumns,
      });
      expect(cells).not.toBeNull();
      expect(cells![expected.ordinal]!.value).toBe(expected.value);
      expect(cells![expected.ordinal]!.quoted).toBe(expected.quoted);
      expect(cells![expected.ordinal]!.bracedGroup===true)
        .toBe(expected.bracedGroup);
    }
  });

  it('does not create fields when explicit context is absent',()=>{
    const test=cases.find(c=>c.id==='BRACED_INNER_COMMAS')!;
    expect(inspectIndependentQuotedCsv(test.wire).disposition).toBe('RAW_ONLY');
    const strict=readCsvSourceCells(test.wire,',',false);
    expect(strict!.length).toBeGreaterThan(test.cells.length);
    const withoutDeclaration=inspectIndependentQuotedCsv(test.wire,{
      recordFraming:'CONFIRMED_SINGLE_CSV_RECORD',
      headerRaw:test.headerRaw,
    });
    expect(withoutDeclaration.disposition).toBe('ABSTAIN_UNSAFE');
    expect(withoutDeclaration.namedClaims).toEqual([]);
    expect(arbitrateOptionalIndependentCsv(test.wire))
      .toEqual(arbitrateOptionalIndependentCsv(test.wire,undefined));
  });

  it('does not bypass an independent source identity or structural veto',()=>{
    const t=cases[0]!;
    for(const veto of [
      {sourceIdentity:'MISMATCH' as const,structuralProfile:'ACCEPT' as const,
        independentSourceTruth:'UNSCORED' as const},
      {sourceIdentity:'MATCH' as const,structuralProfile:'VETO' as const,
        independentSourceTruth:'UNSCORED' as const},
    ]){
      const candidate=inspectIndependentQuotedCsv(t.wire,context(t),veto);
      expect(candidate.disposition).toBe('ABSTAIN_UNSAFE');
      expect(candidate.namedClaims).toEqual([]);
      expect(candidate.autoPromoted).toBe(false);
    }
  });

  it('does not alter RFC4180 standard quoted/escaped syntax',()=>{
    const plain='id,"a,b","doubled ""quote""",';
    const cells=readCsvSourceCells(plain,',',false);
    expect(cells?.map(x=>x.value)).toEqual([
      'id','a,b','doubled "quote"','',
    ]);
    expect(cells?.some(x=>x.bracedGroup)).toBe(false);
  });
});
