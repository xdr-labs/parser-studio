import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {toBackendProject} from './backendAdapter';
import {prepareAutoParserDraft} from './autoParserDraft';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';

const cap={authoring:{extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
  rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const json=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"user":"PRIVATE_OWNER"}',
  '{"action":"deny","src_ip":"203.0.113.2","dst_port":22,"user":"PRIVATE_OTHER"}',
].join('\n');
const sample2=[
  '{"operation":"login","account":{"user":"SECRET_ONE"},"ip":"192.0.2.3"}',
  '{"operation":"logout","account":{"user":"SECRET_TWO"},"ip":"192.0.2.4"}',
].join('\n');
function prepare(sample:string,draft=createDraft()){
 const ledger=analyzeLogEnvelopes(sample,'single-line');
 const assessment=assessEnvelopeCompilation(ledger,cap);
 return prepareAutoParserDraft(sample,draft,preview(sample,draft),ledger,assessment);
}
describe('AP2 zero-forced-format guided novice mapping handoff',()=>{
 it('one explicit review action chooses a homogeneous compiler-supported JSON draft and retains all source',()=>{
   const result=prepare(json);
   expect(result).toMatchObject({ok:true});
   if(!result.ok)return;
   expect(result.draft.format).toBe('json');
   expect(result.draft.mappings).toEqual(expect.arrayContaining([
     expect.objectContaining({source:'action',target:'action',type:'string'}),
     expect.objectContaining({source:'src_ip',target:'srcip',type:'ip'}),
     expect.objectContaining({source:'dst_port',target:'dstport',type:'integer'}),
     expect.objectContaining({source:'user',target:'user',type:'string'}),
   ]));
   expect(result.draft.guided?.groups[result.draft.mappings.find(m=>m.source==='src_ip')!.id]).toBe('top_fields');
   expect(result.draft.guided?.groups[result.draft.mappings.find(m=>m.source==='user')!.id]).toBe('vendor_fields');
   expect(result.draft.guided?.receiver.port).toBe(6801);
   expect(toBackendProject(result.draft)).toMatchObject({ok:true});
   expect(result.requiresApproval).toBe(false);
   expect(result.sourceFieldCount).toBe(4);
   expect(JSON.stringify(result)).not.toContain('PRIVATE_OWNER');
   expect(JSON.stringify(result)).not.toContain('198.51.100.10');
 });
 it('keeps unfamiliar fields vendor-local without fabricating Stellar dictionary fields',()=>{
   const result=prepare(sample2);
   expect(result.ok).toBe(true);
   if(!result.ok)return;
   expect(result.draft.format).toBe('json');
   expect(result.draft.mappings.map(m=>m.source).sort()).toEqual(['account.user','ip','operation']);
   expect(result.draft.mappings.every(m=>!m.target.startsWith('custom.'))).toBe(true);
   expect(result.draft.mappings.every(m=>result.draft.guided?.groups[m.id]==='vendor_fields')).toBe(true);
   expect(result.draft.mappings.find(m=>m.source==='ip')?.type).toBe('ip');
   expect(result.draft.guided?.classification.rules).toEqual([]);
   expect(toBackendProject(result.draft).ok).toBe(true);
   expect(JSON.stringify(result)).not.toContain('SECRET_ONE');
 });
 it('types vendor JSON numbers and booleans from the JSON itself, never from strings or single observations',()=>{
   const lines=[
     {gid:1,rev:7,flag:true,label:'a',ratio:1.5,mixed:1,code:'007',big:9007199254740993,once:5,partial:3},
     {gid:1,rev:9,flag:false,label:'b',ratio:2,mixed:'x',code:'043',big:9007199254740993,partial:4},
     {gid:2,rev:-3,flag:true,label:'c',ratio:3,mixed:2,code:'112',big:9007199254740993},
   ].map(item=>JSON.stringify(item)).join('\n');
   const result=prepare(lines);
   expect(result.ok).toBe(true);
   if(!result.ok)return;
   const type=(source:string)=>result.draft.mappings.find(m=>m.source===source)?.type;
   expect(type('gid')).toBe('integer');
   expect(type('rev')).toBe('integer');
   expect(type('flag')).toBe('boolean');
   // present in only two of three events, but every observed value is a JSON integer
   expect(type('partial')).toBe('integer');
   // one observation is not enough evidence
   expect(type('once')).toBe('string');
   // text, fractions, mixed kinds and integers beyond the exact range stay text
   expect(type('label')).toBe('string');
   expect(type('ratio')).toBe('string');
   expect(type('mixed')).toBe('string');
   expect(type('code')).toBe('string');
   expect(type('big')).toBe('string');
   expect(toBackendProject(result.draft)).toMatchObject({ok:true});
   const replay=preview(lines,result.draft);
   expect(replay.counts.failures).toBe(0);
   expect(replay.counts.normalized).toBe(replay.counts.total);
 });
 it('keeps dictionary-matched and user-visible top-level mappings unchanged by native type inference',()=>{
   const lines=[
     '{"src_ip":"198.51.100.10","dst_port":443,"flow_id":1805461738637437}',
     '{"src_ip":"203.0.113.2","dst_port":22,"flow_id":1805461738637438}',
   ].join('\n');
   const result=prepare(lines);
   expect(result.ok).toBe(true);
   if(!result.ok)return;
   expect(result.draft.mappings.find(m=>m.source==='src_ip')).toMatchObject({target:'srcip',type:'ip'});
   expect(result.draft.mappings.find(m=>m.source==='dst_port')).toMatchObject({target:'dstport',type:'integer'});
   expect(result.draft.mappings.find(m=>m.source==='flow_id')?.type).toBe('integer');
 });
 it('does not auto-map observed empty values that would make an otherwise valid sample fail normalization',()=>{
   const source=[
    '{"event":"allow","httpRequest":{"args":"","clientIp":"192.0.2.10"}}',
    '{"event":"deny","httpRequest":{"args":"","clientIp":"192.0.2.11"}}',
   ].join('\n');
   const result=prepare(source);
   expect(result.ok).toBe(true);
   if(!result.ok)return;
   expect(result.draft.mappings.map(m=>m.source)).toContain('event');
   expect(result.draft.mappings.map(m=>m.source)).toContain('httpRequest.clientIp');
   expect(result.draft.mappings.map(m=>m.source)).not.toContain('httpRequest.args');
   expect(preview(source,result.draft).counts).toMatchObject({
    total:2,matched:2,extracted:2,normalized:2,failures:0,
   });
 });
 it('never overwrites customized approved mapping when the user has already edited it',()=>{
   const draft=createDraft();draft.mappings[0]!.target='custom.owner_choice';
   const r=prepare(sample2,draft);
   expect(r.ok).toBe(true);
   if(!r.ok)return;
   expect(r.draft.mappings[0]?.target).toBe('custom.owner_choice');
   expect(r.draft.mappings.length).toBe(draft.mappings.length);
   expect(r.requiresApproval).toBe(true);
   expect(JSON.stringify(r)).not.toContain('SECRET_ONE');
 });
 it('blocks recognized mixed samples on older backends, plus malformed/unknown and multiline',()=>{
   const inputs=[
     [json+'\naction=deny src_ip=198.51.100.10','COMPILER_UNSUPPORTED'],
     ['<34>Oct 12 13:14:15 fw app: action=allow','COMPILER_UNSUPPORTED'],
     [json+'\nCUSTOMER_UNKNOWN_PRIVATE','MIXED_OR_UNKNOWN'],
     ['{"broken":','MIXED_OR_UNKNOWN'],
   ] as const;
   for(const [input,reason] of inputs){
     const result=prepare(input);
     expect(result.ok).toBe(false);
     if(!result.ok)expect(result.reason).toBe(reason);
   }
 });
 it('disables exports for false native/target verification claims and stale browser snapshots',()=>{
   const draft=createDraft();
   const report=analyzeLogEnvelopes(json,'single-line');
   const assessment=assessEnvelopeCompilation(report,cap);
   const suite=preview(json,draft);
   suite.nativeFluentdVerified=true as false;
   expect(prepareAutoParserDraft(json,draft,suite,report,assessment)).toMatchObject({
     ok:false,reason:'UNTRUSTED_PREVIEW'});
 });
});
