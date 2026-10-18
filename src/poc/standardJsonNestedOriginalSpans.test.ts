import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {inspectSourceCompleteness} from '../standardSourceCompletenessGate';

type Claim={
  pointer:string;nameRawLexeme:string|null;
  nameStartByte:number|null;nameEndByte:number|null;
  valueRawLexeme:string;valueStartByte:number;valueEndByte:number;
};
type Case={
  id:string;wire:string;
  expectedDisposition:'REVIEW_ONLY_LEXICAL'|'REVIEW_ONLY_UNCERTAIN'|'ABSTAIN_UNSAFE';
  expectedIssues:string[];claims:Claim[];
  sourceBytes:number;sourceSha256:string;
};
const bytes=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardJsonNestedOriginalSpans.pinned.json'));
const manifestSha='03c6e1ae49a5cfb2c2c034d4ae584e777115acecdb08d006928286ff1db614e0';
const sha=(raw:Uint8Array)=>createHash('sha256').update(raw).digest('hex');
if(sha(bytes)!==manifestSha)
 throw Error('Original independently authored RFC8259/6901 JSON field span oracle changed');
const {cases}=JSON.parse(bytes.toString('utf8')) as {cases:Case[]};
const decoder=new TextDecoder('utf8',{fatal:true});

describe('P0-STD RFC8259 nested JSON ordered original UTF-8 byte-source field spans',()=>{
  it('pins separate authored original source and negative denominators',()=>{
    expect(cases).toHaveLength(18);
    expect(cases.filter(x=>x.expectedDisposition==='REVIEW_ONLY_LEXICAL')).toHaveLength(9);
    expect(cases.filter(x=>x.expectedDisposition!=='REVIEW_ONLY_LEXICAL')).toHaveLength(9);
    expect(cases.flatMap(x=>x.claims)).toHaveLength(32);
  });
  it.each(cases)('matches declared JSON Pointer and original field bytes: $id',c=>{
    const original=new TextEncoder().encode(c.wire);
    expect(original).toHaveLength(c.sourceBytes);
    expect(sha(original)).toBe(c.sourceSha256);
    const result=inspectSourceCompleteness(c.wire,'json');
    expect(result.sourceBytes).toBe(c.sourceBytes);
    expect(result.raw).toBe(c.wire);
    expect(result.family).toBe('json');
    expect(result.disposition).toBe(c.expectedDisposition);
    expect(result.issues).toEqual(expect.arrayContaining(c.expectedIssues));
    expect(result.sourceFieldValuesDecoded).toBe(false);
    expect(result.nativeStellar).toBe('NOT_VERIFIED');
    expect(result.completeSourceClaim).toBe(false);
    expect(result.autoPromoted).toBe(false);
    if(c.expectedDisposition!=='REVIEW_ONLY_LEXICAL'){
      // Never leak even apparently plausible prefixes as field claims
      // after a duplicate key, number-loss risk, malformed or bounded input.
      expect(result.jsonRawSpans).toEqual([]);
      expect(result.namedRawFields).toEqual([]);
      return;
    }
    expect(result.jsonRawSpans).toHaveLength(c.claims.length);
    c.claims.forEach((expected,i)=>{
      const actual=result.jsonRawSpans[i]!;
      expect({
        pointer:actual.pointer,
        nameRawLexeme:actual.nameRawLexeme,
        nameStartByte:actual.nameStartByte,
        nameEndByte:actual.nameEndByte,
        valueRawLexeme:actual.valueRawLexeme,
        valueStartByte:actual.valueStartByte,
        valueEndByte:actual.valueEndByte,
      }).toEqual(expected);
      expect(decoder.decode(original.subarray(
        actual.valueStartByte,actual.valueEndByte))).toBe(expected.valueRawLexeme);
      if(expected.nameRawLexeme!==null){
        expect(decoder.decode(original.subarray(
          actual.nameStartByte!,actual.nameEndByte!))).toBe(expected.nameRawLexeme);
      }else{
        expect(actual.nameStartByte).toBeNull();
        expect(actual.nameEndByte).toBeNull();
      }
    });
    // This is only a lexical source observer. No native/source-complete
    // confidence or manufacturer field-meaning promotion follows.
    expect(result.namedRawFields).toEqual([]);
  });
});
