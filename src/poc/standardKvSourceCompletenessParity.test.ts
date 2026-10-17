import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {extractFields} from '../parser';
import {createDraft} from '../model';
import {extractStructuredFamily,strictKeyValues} from '../structuredFamilies';
import {inspectSourceCompleteness} from '../standardSourceCompletenessGate';

type Claim={name:string;rawLexeme:string;decoded:string;
 nameStartByte:number;nameEndByte:number;valueStartByte:number;valueEndByte:number};
type TestCase={id:string;wire:string;disposition:'REVIEW_ONLY_LEXICAL'|'REVIEW_ONLY_UNCERTAIN';
 issues:string[];claims:Claim[];sourceBytes:number};
const frozen=fs.readFileSync(path.join(__dirname,
 '../../scripts/poc/standardKvSourceCompleteness.pinned.json'));
const sha='831e755960e47b5b98844080c80f2a76966e9e51e6b291813d2ac18c86cf8127';
if(createHash('sha256').update(frozen).digest('hex')!==sha)
 throw Error('Frozen independently authored KV source-completeness truth drifted');
const {cases}=JSON.parse(frozen.toString('utf8')) as {cases:TestCase[]};
const prefix='<34>1 2026-10-18T12:34:56Z edge app 1 EVENT - ';
const decoder=new TextDecoder('utf-8',{fatal:true});

describe('P0-STD-7 generic KV source completeness / unknown escape review',()=>{
 it('pins synthetic case denominators before candidate scoring',()=>{
  expect(cases).toHaveLength(14);
  expect(cases.filter(c=>c.disposition==='REVIEW_ONLY_LEXICAL')).toHaveLength(5);
  expect(cases.filter(c=>c.disposition==='REVIEW_ONLY_UNCERTAIN')).toHaveLength(9);
 });
 it.each(cases)('never upgrades unconsumed or unqualified KV source: $id',test=>{
  const raw=new TextEncoder().encode(test.wire);
  expect(raw.length).toBe(test.sourceBytes);
  const source=inspectSourceCompleteness(test.wire,'kv');
  expect(source.disposition).toBe(test.disposition);
  expect(source.issues).toEqual(expect.arrayContaining(test.issues));
  expect(source.completeSourceClaim).toBe(false);
  expect(source.sourceFieldValuesDecoded).toBe(false);
  expect(source.nativeStellar).toBe('NOT_VERIFIED');
  expect(source.autoPromoted).toBe(false);
  const candidate=extractFields(test.wire,'kv',createDraft());
  const lexical=strictKeyValues(test.wire);
  const nested=extractStructuredFamily(prefix+test.wire,'syslog_rfc5424','kv');
  const valid=test.disposition==='REVIEW_ONLY_LEXICAL';
  expect(candidate.errors.length===0).toBe(valid);
  expect(lexical.errors.length===0).toBe(valid);
  expect(nested.errors.length===0).toBe(valid);
  if(!valid){
   expect(source.namedRawFields).toEqual([]);
   expect(candidate.fields).toEqual({});
   return;
  }
  expect(source.namedRawFields).toHaveLength(test.claims.length);
  for(const item of test.claims){
   const observed=source.namedRawFields.find(x=>x.name===item.name);
   expect(observed).toMatchObject({
    name:item.name,rawLexeme:item.rawLexeme,
    nameStartByte:item.nameStartByte,nameEndByte:item.nameEndByte,
    valueStartByte:item.valueStartByte,valueEndByte:item.valueEndByte,
   });
   expect(decoder.decode(raw.subarray(item.nameStartByte,item.nameEndByte))).toBe(item.name);
   expect(decoder.decode(raw.subarray(item.valueStartByte,item.valueEndByte))).toBe(item.rawLexeme);
   expect(candidate.fields[item.name]).toBe(item.decoded);
   expect(lexical.fields[item.name]).toBe(item.decoded);
   expect((nested.fields.body as Record<string,unknown>)[item.name]).toBe(item.decoded);
  }
 });
});
