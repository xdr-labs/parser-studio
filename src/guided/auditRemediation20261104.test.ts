import {describe,it,expect} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {hasAmbiguousFieldPath} from '../fieldPaths';
import {validatePreviewRegexPattern} from '../regexSafety';
import {JSONATA_MAPPING_CONTRACT,createJsonataMappingPrompt,reviewJsonataMapping,
  applyReviewedJsonataMapping,parseJsonataSelector,pathToJsonataSelector} from './jsonataMappingAssist';

const makeDraft=(mappings:ParserDraft['mappings']=[]):ParserDraft=>{
  const base=createDraft();
  return {...base,format:'json',mappings,
    guided:{...base.guided!,groups:Object.fromEntries(mappings.map(m=>[m.id,'top_fields'])),
      classification:{defaultIndex:'Syslog',rules:[]}}};
};
const answer=(hash:string,events:number,mappings:Array<{expression:string;target:string}>)=>
  JSON.stringify({contract:JSONATA_MAPPING_CONTRACT,
    sample:{sha256:hash,events},mappings});

describe('2026-11-04 independent audit remediation - exact field identity',()=>{
 it('refuses competing flat dotted and nested values instead of silently choosing the wrong IP',async()=>{
   const fields={'source.ip':'203.0.113.47',source:{ip:'192.0.2.19'}};
   expect(hasAmbiguousFieldPath(fields,'source.ip')).toBe(true);
   expect(hasAmbiguousFieldPath({'source.ip':'203.0.113.47'},'source.ip')).toBe(false);
   expect(hasAmbiguousFieldPath({source:{ip:'192.0.2.19'}},'source.ip')).toBe(false);
   const raw=JSON.stringify(fields);
   const mapped=makeDraft([{id:'ip',source:'source.ip',target:'srcip',type:'ip'}]);
   const output=preview(raw,mapped);
   expect(output.events[0]?.normalized).not.toHaveProperty('srcip');
   expect(output.events[0]?.diagnostics).toEqual(expect.arrayContaining([
     expect.objectContaining({code:'AMBIGUOUS_SOURCE_PATH',severity:'error'}),
   ]));
   expect(output.events[0]?.normalizedOk).toBe(false);
   const suite=preview(raw,makeDraft());
   await expect(createJsonataMappingPrompt(suite,makeDraft())).rejects.toThrow(/ambiguous dotted keys/);
 });
 it('quotes a literal dotted root JSON key with one segment and refuses misleading unquoted JSONata',async()=>{
   const draft=makeDraft();
   const suite=preview('{"source.ip":"203.0.113.47"}',draft);
   const {prompt,sha256}=await createJsonataMappingPrompt(suite,draft);
   expect(prompt).toContain('"selector":"`source.ip`"');
   expect(pathToJsonataSelector('source.ip',true)).toBe('`source.ip`');
   expect(parseJsonataSelector('`source.ip`')).toBe('source.ip');
   expect(parseJsonataSelector('obj.`broken.key`')).toBeNull();
   const wrong=await reviewJsonataMapping(answer(sha256,1,[{expression:'source.ip',target:'srcip'}]),
     suite,draft,sha256);
   expect(wrong.ok).toBe(true);
   if(wrong.ok)expect(wrong.rows[0]?.status).toBe('BLOCKED');
   const good=await reviewJsonataMapping(answer(sha256,1,[{expression:'`source.ip`',target:'srcip'}]),
     suite,draft,sha256);
   expect(good.ok).toBe(true);
   if(!good.ok)return;
   expect(good.rows[0]?.status).not.toBe('BLOCKED');
   const applied=applyReviewedJsonataMapping(draft,suite,good.rows);
   expect(applied.ok).toBe(true);
   if(applied.ok)expect(preview('{"source.ip":"203.0.113.47"}',applied.draft).events[0]?.normalized)
     .toMatchObject({srcip:'203.0.113.47'});
 });
 it('preserves normal nested paths and refuses mixed flat/nested semantics across events',async()=>{
   const draft=makeDraft();
   const nested=preview('{"source":{"ip":"192.0.2.19"}}',draft);
   const prompt=await createJsonataMappingPrompt(nested,draft);
   expect(prompt.prompt).toContain('"selector":"source.ip"');
   const reviewed=await reviewJsonataMapping(answer(prompt.sha256,1,[{expression:'source.ip',target:'srcip'}]),
     nested,draft,prompt.sha256);
   expect(reviewed.ok).toBe(true);
   if(reviewed.ok)expect(reviewed.rows[0]?.status).not.toBe('BLOCKED');
   const mixed=preview('{"source.ip":"203.0.113.47"}\n{"source":{"ip":"192.0.2.19"}}',draft);
   await expect(createJsonataMappingPrompt(mixed,draft)).rejects.toThrow(/ambiguous dotted keys/);
 });
 it('does not silently omit fields when source field count exceeds the mapping contract',async()=>{
   const sample=Object.fromEntries(Array.from({length:115},(_,i)=>['field'+i,'value'+i]));
   const draft=makeDraft();
   const suite=preview(JSON.stringify(sample),draft);
   expect(Object.keys(suite.events[0]!.fields)).toHaveLength(115);
   await expect(createJsonataMappingPrompt(suite,draft)).rejects.toThrow(/more than 100 parsed source fields/);
 });
 it('enforces IP protocol number and L4 protocol name semantics before and after AI review',async()=>{
   const draft=makeDraft();
   const raw='{"protocol-id":"999","protocol":"HTTPS"}';
   const suite=preview(raw,draft);
   const {sha256}=await createJsonataMappingPrompt(suite,draft);
   const reviewed=await reviewJsonataMapping(answer(sha256,1,[
     {expression:'`protocol-id`',target:'proto'},
     {expression:'protocol',target:'proto_name'},
   ]),suite,draft,sha256);
   expect(reviewed.ok).toBe(true);
   if(!reviewed.ok)return;
   expect(reviewed.rows.map(r=>r.status)).toEqual(['BLOCKED','BLOCKED']);
   expect(applyReviewedJsonataMapping(draft,suite,reviewed.rows)).toMatchObject({ok:false});
   const direct=makeDraft([
     {id:'p',source:'protocol-id',target:'proto',type:'integer'},
     {id:'n',source:'protocol',target:'proto_name',type:'string'},
   ]);
   const invalid=preview(raw,direct);
   expect(invalid.events[0]?.diagnostics.filter(x=>x.code==='TYPE_ERROR')).toHaveLength(2);
   expect(invalid.events[0]?.normalized).not.toHaveProperty('proto');
   expect(invalid.events[0]?.normalized).not.toHaveProperty('proto_name');
   const valid=preview('{"protocol-id":6,"protocol":"TCP"}',direct);
   expect(valid.events[0]?.normalized).toMatchObject({proto:6,proto_name:'TCP'});
 });
 it('rejects nested counted repetition before synchronous preview execution',()=>{
   const patterns=['^(?<field>(a{1,3})+)$','^(?<field>(?:a{1,3}){2,10})$'];
   for(const pattern of patterns){
     expect(validatePreviewRegexPattern(pattern),pattern).not.toBeNull();
     const base=createDraft();
     const result=preview('a'.repeat(40)+'!',{...base,format:'regex',pattern});
     expect(result.events[0]?.matched).toBe(false);
     expect(result.events[0]?.diagnostics).toEqual(expect.arrayContaining([
       expect.objectContaining({code:'EXTRACTION_FAILED'}),
     ]));
   }
   expect(validatePreviewRegexPattern('^(?<field>a{1,3})$')).toBeNull();
 });
});
