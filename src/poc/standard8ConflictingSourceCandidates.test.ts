import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {inspectGrammarFunnel} from './grammarFunnel';

type Case={
 id:string;raw:string;expectedDisposition:string;baselineOk:boolean;
 expectedCandidateFamilies:string[];sourceBytes:number;sourceSha256:string;
};
const bytes=fs.readFileSync(path.join(__dirname,
 '../../scripts/poc/standard8ConflictingSourceCandidates.pinned.json'));
const sha='c51b4f4f2dbcd8d2675b2ba7aaae8014467a2f54f3c310b5121d8b246eddbfa6';
if(createHash('sha256').update(bytes).digest('hex')!==sha)
 throw Error('Independent STD-8 source-conflict oracle has drifted');
const {cases}=JSON.parse(bytes.toString('utf8')) as {cases:Case[]};

describe('P0-STD-8 bounded source grammar conflict/adjudication safety',()=>{
 it('uses a frozen synthetic-only independent outcome registry',()=>{
   expect(cases).toHaveLength(14);
   expect(cases.filter(c=>c.expectedDisposition==='ambiguous')).toHaveLength(4);
   expect(cases.filter(c=>c.expectedDisposition==='partial_candidate')).toHaveLength(2);
   expect(cases.filter(c=>c.expectedDisposition==='candidate_only')).toHaveLength(3);
 });
 it.each(cases)('does not choose a field schema absent original-source evidence: $id',c=>{
   const received=new TextEncoder().encode(c.raw);
   expect(received).toHaveLength(c.sourceBytes);
   expect(createHash('sha256').update(received).digest('hex')).toBe(c.sourceSha256);
   const out=inspectGrammarFunnel(c.raw,c.baselineOk);
   expect(out.disposition).toBe(c.expectedDisposition);
   expect(out.passes).toBe(2);
   for(const evidence of out.candidates){
     expect(evidence.tokenSpansReplayed).toBe(true);
     expect(evidence.sourceOracleVerified).toBe(false);
     expect(evidence.bodyBytes).toBeLessThanOrEqual(c.sourceBytes);
     expect(evidence.fieldCount).toBeGreaterThanOrEqual(2);
   }
   for(const grammar of c.expectedCandidateFamilies)
     expect(out.candidates.map(x=>x.grammar)).toContain(grammar);
   if(['ambiguous','raw_only','invalid_envelope','baseline_preserved'].includes(c.expectedDisposition)){
     expect(out.selected).toBeNull();
   }else{
     expect(out.selected?.sourceOracleVerified).toBe(false);
     expect(out.selected?.tokenSpansReplayed).toBe(true);
   }
   if(c.expectedDisposition==='ambiguous'){
     expect(out.candidates.length).toBeGreaterThanOrEqual(2);
     expect(out.note).toContain('interpretations');
   }
   if(c.expectedDisposition==='partial_candidate'){
     expect(out.selected?.fullBodyCovered).toBe(false);
   }
   // A syntax candidate is never proof of producer-provided fields/native semantics.
   expect(inspectGrammarFunnel(c.raw,c.baselineOk)).toEqual(out);
 });
});
