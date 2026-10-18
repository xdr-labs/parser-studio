import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {parseW3cLogBlock} from '../w3cTabular';

type Field={
 rowIndex:number;name:string;rawLexeme:string;decodedValue:string;
 startByte:number;endByte:number;
};
type Case={
 id:string;wire:string;validV1:boolean;claims:Field[];expectedRows:number;
 expectedFields?:string[];lineEnding?:'lf'|'crlf';sourceBytes:number;sourceSha256:string;
};
const frozen=fs.readFileSync(path.join(__dirname,
 '../../scripts/poc/standardW3cRequiredDeclarations.pinned.json'));
const expectedHash='c51f6586c0d74c1bb3d968b5d38cc71131032d435d40eb280c15224ea5350984';
if(createHash('sha256').update(frozen).digest('hex')!==expectedHash)
 throw Error('Independently frozen W3C v1 directive source oracle changed');
const {cases}=JSON.parse(frozen.toString('utf8')) as {cases:Case[]};
const sha=(value:Uint8Array)=>createHash('sha256').update(value).digest('hex');
const decoder=new TextDecoder('utf-8',{fatal:true});

describe('P0-STD W3C v1 mandatory declarations and source byte spans',()=>{
 it('has independently pinned positive/negative source denominators',()=>{
   expect(cases).toHaveLength(18);
   expect(cases.filter(c=>c.validV1)).toHaveLength(6);
   expect(cases.filter(c=>!c.validV1)).toHaveLength(12);
 });
 it.each(cases)('requires W3C v1 Version and Fields before original data: $id',sample=>{
   const original=new TextEncoder().encode(sample.wire);
   expect(original).toHaveLength(sample.sourceBytes);
   expect(sha(original)).toBe(sample.sourceSha256);
   const output=parseW3cLogBlock(sample.wire);
   expect(output.ok).toBe(sample.validV1);
   if(!output.ok){
     expect(output.error.length).toBeGreaterThan(0);
     return;
   }
   expect(output.block.directives.Version).toBe('1.0');
   expect(output.block.schema.fields).toEqual(sample.expectedFields);
   expect(output.block.rows).toHaveLength(sample.expectedRows);
   expect(output.block.lineEnding).toBe(sample.lineEnding);
   expect(output.block.sourceBytes).toBe(sample.sourceBytes);
   const observed=output.block.rowFieldSpans.flat();
   expect(observed).toHaveLength(sample.claims.length);
   sample.claims.forEach((field,i)=>{
     const actual=observed[i]!;
     expect(actual.name).toBe(field.name);
     expect(actual.rawLexeme).toBe(field.rawLexeme);
     expect(actual.startByte).toBe(field.startByte);
     expect(actual.endByte).toBe(field.endByte);
     expect(decoder.decode(original.subarray(field.startByte,field.endByte)))
       .toBe(field.rawLexeme);
     expect(output.block.rows[field.rowIndex]?.[field.name]).toBe(field.decodedValue);
   });
 });
});
