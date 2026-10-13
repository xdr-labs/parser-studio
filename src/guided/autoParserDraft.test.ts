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
   expect(result.draft.mappings).toEqual(createDraft().mappings);
   expect(result.draft.guided?.receiver.port).toBe(7501);
   expect(toBackendProject(result.draft)).toMatchObject({ok:true});
   expect(result.requiresApproval).toBe(false);
   expect(result.sourceFieldCount).toBe(4);
   expect(JSON.stringify(result)).not.toContain('PRIVATE_OWNER');
   expect(JSON.stringify(result)).not.toContain('198.51.100.10');
 });
 it('suggests only conservative custom paths from a different sample with no fabricated Stellar official fields',()=>{
   const result=prepare(sample2);
   expect(result.ok).toBe(true);
   if(!result.ok)return;
   expect(result.draft.format).toBe('json');
   expect(result.draft.mappings.map(m=>m.source).sort()).toEqual(['account.user','ip','operation']);
   expect(result.draft.mappings.every(m=>m.target.startsWith('custom.'))).toBe(true);
   expect(result.draft.mappings.find(m=>m.source==='ip')?.type).toBe('ip');
   expect(result.draft.guided?.classification.rules).toEqual([]);
   expect(toBackendProject(result.draft).ok).toBe(true);
   expect(JSON.stringify(result)).not.toContain('SECRET_ONE');
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
