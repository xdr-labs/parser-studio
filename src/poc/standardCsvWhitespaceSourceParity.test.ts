import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {extractFields} from '../parser';
import {parseRfc4180SingleDataRow} from '../rfc4180Csv';
import {inspectIndependentQuotedCsv} from './independentQuotedCsvSource';

type Cell={
  ordinal:number;rawLexeme:string;decoded:string;quoted:boolean;
  startByte:number;endByte:number;nullableSourceValue:string|null;
};
type Row={id:string;wire:string;valid:boolean;claims:Cell[];sourceBytes:number};
const raw=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardsCsvWhitespaceSource.pinned.json'));
const hash='02ec194375d84f36b9dc78e4c0bb9c8b298c43bbbbeb96809e2eaaa67be9f09e';
if(createHash('sha256').update(raw).digest('hex')!==hash)
  throw Error('Frozen RFC4180 source oracle drifted');
const {cases}=JSON.parse(raw.toString('utf8')) as {cases:Row[]};
const draft={...createDraft(),csvColumns:'first,second,third',csvDelimiter:',' as const};
const ctx={
  recordFraming:'CONFIRMED_SINGLE_CSV_RECORD' as const,
  headerRaw:'first,second,third',
  treatUnquotedEmptyAsNull:true,
};
describe('P0-STD-6 RFC4180 browser/source single-record UTF-8 exact parity',()=>{
  it('pins expected independent synthetic denominator',()=>{
    expect(cases).toHaveLength(14);
    expect(cases.filter(x=>x.valid)).toHaveLength(9);
    expect(cases.filter(x=>!x.valid)).toHaveLength(5);
  });
  it.each(cases)('preserves field edge spaces and source spans: $id',c=>{
    const bytes=new TextEncoder().encode(c.wire);
    expect(bytes.length).toBe(c.sourceBytes);
    const source=inspectIndependentQuotedCsv(c.wire,ctx);
    const browser=extractFields(c.wire,'csv',draft);
    const single=parseRfc4180SingleDataRow(c.wire);
    expect(browser.errors.length===0).toBe(c.valid);
    expect(single!==null).toBe(c.valid);
    if(!c.valid){
      expect(source.disposition).toBe('ABSTAIN_UNSAFE');
      expect(source.positionalClaims).toEqual([]);
      expect(source.namedClaims).toEqual([]);
      expect(source.autoPromoted).toBe(false);
      return;
    }
    expect(source.disposition).toBe('REVIEW_ONLY_NAMED');
    expect(source.namedClaims).toHaveLength(c.claims.length);
    expect(single?.values).toEqual(c.claims.map(x=>x.decoded));
    for(const item of c.claims){
      const observed=source.positionalClaims[item.ordinal]!;
      const named=source.namedClaims[item.ordinal]!;
      expect({ordinal:observed.ordinal,value:observed.value,
        rawValueSpan:observed.rawValueSpan,startByte:observed.startByte,
        endByte:observed.endByte}).toEqual({
          ordinal:item.ordinal,value:item.nullableSourceValue,
          rawValueSpan:item.rawLexeme,startByte:item.startByte,endByte:item.endByte,
        });
      expect(named.name).toBe(['first','second','third'][item.ordinal]);
      expect(browser.fields[named.name]).toBe(item.decoded);
      expect(new TextDecoder('utf8',{fatal:true})
        .decode(bytes.subarray(item.startByte,item.endByte))).toBe(item.rawLexeme);
    }
    expect(source.autoPromoted).toBe(false);
    expect(source.nativeVerified).toBe(false);
    expect(source.independentOracleCertified).toBe(false);
  });
});
