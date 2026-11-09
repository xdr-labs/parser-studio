import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {describe,it,expect} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {toBackendProject} from './backendAdapter';
import {JSONATA_MAPPING_CONTRACT,parseJsonataSelector,pathToJsonataSelector,
 createJsonataMappingPrompt,reviewJsonataMapping,applyReviewedJsonataMapping} from './jsonataMappingAssist';

const raw=[
 '{"src_ip":"192.0.2.10","dst_ip":"198.51.100.20","action":"allow"}',
 '{"src_ip":"192.0.2.11","dst_ip":"198.51.100.21","action":"deny"}',
].join('\n');
function setup(){
 const base=createDraft();
 const draft:ParserDraft={...base,format:'json',mappings:[
  {id:'s',source:'src_ip',target:'vendor_src',type:'string'},
  {id:'d',source:'dst_ip',target:'vendor_dst',type:'string'},
  {id:'a',source:'action',target:'action',type:'string'},
 ],guided:{...base.guided!,groups:{s:'vendor_fields',d:'vendor_fields',a:'top_fields'}}};
 return {draft,suite:preview(raw,draft)};
}
function answer(sha256:string,events:number,items:Array<{expression:string;target:string}>){
 return JSON.stringify({contract:JSONATA_MAPPING_CONTRACT,sample:{sha256,events},mappings:items});
}
describe('review-only JSONata source selector mapping',()=>{
 it('supports backtick selectors but no functions, arithmetic, arrays, or dynamic evaluation',()=>{
  expect(parseJsonataSelector('$.syslog_sd.element_1.params.`source-address`'))
    .toBe('syslog_sd.element_1.params.source-address');
  expect(pathToJsonataSelector('syslog_sd.element_1.params.source-address'))
    .toBe('syslog_sd.element_1.params.`source-address`');
  for(const source of [
   '$number(src_ip)*1000','$lookup(src_ip,"name")','src_ip[0]',
   'src_ip + 1','src_ip.($eval("x"))','__proto__.x','src_ip;foo','src_ip..x',
   'service-name','obj.`broken.key`','src_ip.','$.',
  ])expect(parseJsonataSelector(source),source).toBeNull();
 });
 it('creates a privacy-safe copyable prompt with exact source fingerprint',async()=>{
  const {draft,suite}=setup();
  const safe=await createJsonataMappingPrompt(suite,draft);
  expect(safe.prompt).toContain('src_ip');
  expect(safe.prompt).toContain('No raw log text or field values');
  expect(safe.prompt).not.toContain('192.0.2.10');
  const shared=await createJsonataMappingPrompt(suite,draft,true);
  expect(shared.prompt).toContain('192.0.2.10');
  expect(shared.sha256).toBe(safe.sha256);
 });
 it('reviews official mappings across every sample, compiles to Ruby-compatible rules and previews results',async()=>{
  const {draft,suite}=setup();
  const {sha256}=await createJsonataMappingPrompt(suite,draft);
  const reviewed=await reviewJsonataMapping(answer(sha256,2,[
   {expression:'$.src_ip',target:'srcip'},{expression:'dst_ip',target:'dstip'},
  ]),suite,draft,sha256);
  expect(reviewed.ok).toBe(true);
  if(!reviewed.ok)return;
  expect(reviewed.rows.map(x=>x.status)).toEqual(['READY','READY']);
  const applied=applyReviewedJsonataMapping(draft,suite,reviewed.rows);
  expect(applied.ok).toBe(true);
  if(!applied.ok)return;
  expect(applied.draft.mappings.find(m=>m.source==='src_ip'))
    .toMatchObject({id:'s',target:'srcip',type:'ip'});
  expect(applied.draft.guided?.groups.s).toBe('top_fields');
  expect(toBackendProject(applied.draft)).toMatchObject({ok:true});
  const output=preview(raw,applied.draft);
  expect(output.counts).toMatchObject({total:2,matched:2,extracted:2,normalized:2,failures:0});
  expect(output.events[0]?.normalized).toMatchObject({srcip:'192.0.2.10',dstip:'198.51.100.20'});
 });
 it('rejects stale SHA, extra response fields, unknown contract and excess size',async()=>{
  const {draft,suite}=setup();
  const {sha256}=await createJsonataMappingPrompt(suite,draft);
  const result=answer(sha256,2,[{expression:'src_ip',target:'srcip'}]);
  expect(await reviewJsonataMapping(result,suite,draft,'0'.repeat(64))).toMatchObject({ok:false});
  expect(await reviewJsonataMapping(result.replace(JSONATA_MAPPING_CONTRACT,'other'),suite,draft,sha256))
    .toMatchObject({ok:false});
  expect(await reviewJsonataMapping(result+' '.repeat(25000),suite,draft,sha256))
    .toMatchObject({ok:false});
  expect(await reviewJsonataMapping(result.slice(0,-1)+',"extra":1}',suite,draft,sha256))
    .toMatchObject({ok:false});
 });
 it('blocks invalid types, unknown destinations, duplicate mappings and nonselectable JSONata functions',async()=>{
  const {draft,suite}=setup();
  const {sha256}=await createJsonataMappingPrompt(suite,draft);
  const checked=await reviewJsonataMapping(answer(sha256,2,[
   {expression:'$number(src_ip)',target:'srcip'},
   {expression:'unknown',target:'srcip'},
   {expression:'action',target:'srcip'},
   {expression:'src_ip',target:'not_stellar'},
   {expression:'src_ip',target:'srcip'},
   {expression:'dst_ip',target:'srcip'},
  ]),suite,draft,sha256);
  expect(checked.ok).toBe(true);
  if(!checked.ok)return;
  expect(checked.rows.map(r=>r.status)).toEqual(['BLOCKED','BLOCKED','BLOCKED','BLOCKED','BLOCKED','BLOCKED']);
  expect(applyReviewedJsonataMapping(draft,suite,[checked.rows[0]!])).toMatchObject({ok:false});
 });
 it('blocks known NAT/service false friends while allowing semantically uncertain source with explicit review',async()=>{
  const base=createDraft();
  const draft:ParserDraft={...base,format:'json',mappings:[],guided:{...base.guided!,groups:{}}};
  const suite=preview('{"unknown_ip":"192.0.2.10","nat-source-address":"203.0.113.5","service-name":"https"}',draft);
  const {sha256}=await createJsonataMappingPrompt(suite,draft);
  const result=await reviewJsonataMapping(answer(sha256,1,[
   {expression:'unknown_ip',target:'srcip'},
   {expression:'`nat-source-address`',target:'dstip'},
   {expression:'`service-name`',target:'proto_name'},
  ]),suite,draft,sha256);
  expect(result.ok).toBe(true);
  if(!result.ok)return;
  expect(result.rows.map(r=>r.status)).toEqual(['CHECK_FIRST','BLOCKED','BLOCKED']);
 });
 it('refuses a forged READY row at the native mapping apply boundary',()=>{
  const {draft,suite}=setup();
  const attempt=applyReviewedJsonataMapping(draft,suite,[{
   expression:'src_ip',source:'src_ip',target:'dstip',type:'ip',group:'top_fields',
   status:'READY',reason:'forged',observed:2,total:2,values:[],
  }]);
  expect(attempt).toMatchObject({ok:false});
 });
 it('accepts a documented named-port selector with validated numeric ICMP and UDP data',async()=>{
  const original=readFileSync(resolve('tests/fixtures/docs-practice-20261104/01-juniper-srx.log'),'utf8').trimEnd();
  const base=createDraft();
  const source='syslog_sd.element_1.params.source-port';
  const draft:ParserDraft={...base,format:'syslog_rfc5424',
    mappings:[{id:'raw_source_port',source,target:'original_source_port',type:'string'}],
    guided:{...base.guided!,groups:{raw_source_port:'vendor_fields'},
      classification:{defaultIndex:'Syslog',rules:[]}}};
  const suite=preview(original,draft);
  const {sha256}=await createJsonataMappingPrompt(suite,draft);
  const reviewed=await reviewJsonataMapping(answer(sha256,2,[
    {expression:'syslog_sd.element_1.params.\x60source-port\x60',target:'srcport'},
  ]),suite,draft,sha256);
  expect(reviewed.ok).toBe(true);
  if(!reviewed.ok)return;
  expect(reviewed.rows).toMatchObject([{status:'READY',observed:2,total:2}]);
  expect(reviewed.rows[0]?.when).toBeUndefined();
  // Models cannot forge a conditional expression for an unconditional rule.
  const forged={...reviewed.rows[0]!,when:{sourcePath:'syslog_sd.element_1.params.protocol-id',
    operator:'in' as const,values:['1']}};
  expect(applyReviewedJsonataMapping(draft,suite,[forged])).toMatchObject({ok:false});
  const applied=applyReviewedJsonataMapping(draft,suite,reviewed.rows);
  expect(applied.ok,applied.ok?"":applied.reason).toBe(true);
  if(!applied.ok)return;
  expect(applied.draft.mappings.filter(m=>m.source===source)).toHaveLength(1);
  expect(toBackendProject(applied.draft)).toMatchObject({ok:true});
  const output=preview(original,applied.draft);
  expect(output.counts.failures).toBe(0);
  expect(output.events[0]?.normalized.srcport).toBe(594);
  expect(output.events[1]?.normalized.srcport).toBe(37233);
  expect(output.events[0]?.fields.syslog_sd).toBeDefined();
 });
 it('blocks PAN-OS event type as a Windows-agent Stellar type',async()=>{
  const base=createDraft();
  const draft:ParserDraft={...base,format:'json',mappings:[],guided:{...base.guided!,groups:{}}};
  const suite=preview('{"generic":{"fields":{"type":"TRAFFIC"}}}',draft);
  const {sha256}=await createJsonataMappingPrompt(suite,draft);
  const result=await reviewJsonataMapping(answer(sha256,1,[
   {expression:'generic.fields.type',target:'type'},
  ]),suite,draft,sha256);
  expect(result.ok).toBe(true);
  if(result.ok)expect(result.rows[0]).toMatchObject({status:'BLOCKED'});
 });
});
