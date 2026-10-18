import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe} from './parserRecipeV2';
import type {BackendCapabilities} from './backendCapabilities';

const source=[
 '{"src_ip":"192.0.2.10","action":"deny"}',
 'src_ip=198.51.100.8 action=allow',
 '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - {"src_ip":"192.0.2.19","action":"deny"}',
 '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - src_ip=203.0.113.4 action=allow',
].join('\n');
const before={authoring:{
 extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
 strictMixedRequiresExplicitAllowlist:true,
 strictMixedSingleLineFamilies:['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv'],
 rfc3164StrictTaggedMessageSubset:true,
 rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',
 rfc3164NativeTimeReconstruction:false,
 rfc3164BodyFormats:['raw','json','kv','cef','leef'],
 rfc5424BodyFormats:['raw','json','kv','cef','leef'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const current={...before,authoring:{...before.authoring,
 strictMixedSingleLineFamilies:[
  'json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv',
 ] as BackendCapabilities['authoring']['strictMixedSingleLineFamilies']
}} as BackendCapabilities;
describe('P0 strict RFC5424 JSON/KV mixed in no-code builder and reviewed Recipe v0.2',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('classifies four source events, preserves explicit timezone and generates a valid staged mixed project',async()=>{
  const draft=createDraft(),initial=preview(source,draft);
  const census=analyzeLogEnvelopes(source,'single-line');
  expect(census).toMatchObject({sourceCount:4,accounted:4,unsupported:0});
  expect(census.families.map(f=>f.envelope+':'+f.body).sort()).toEqual([
   'none:json','none:kv','rfc5424:json','rfc5424:kv']);
  expect(census.events[2]).toMatchObject({timePolicy:'EXPLICIT_TIME'});
  const result=assessEnvelopeCompilation(census,current);
  expect(result).toMatchObject({status:'DRAFT_COMPILABLE',
   format:'mixed',mixedFormats:['json','kv','rfc5424_json','rfc5424_kv'],
   nativeVerified:false,targetVerified:false});
  const ready=prepareAutoParserDraft(source,draft,initial,census,result);
  expect(ready.ok).toBe(true);
  if(!ready.ok)return;
  const p=toBackendProject(ready.draft);
  expect(p).toMatchObject({ok:true,project:{extraction:{
   format:'mixed',mixedFormats:['json','kv','rfc5424_json','rfc5424_kv']}}});
  expect(ready.draft.guided?.receiver.port).toBeGreaterThanOrEqual(6800);
  const full=preview(source,ready.draft);
  expect(full.counts).toMatchObject({total:4,matched:4,extracted:4,normalized:4,failures:0});
  expect(full.events[2]?.fields).toMatchObject({
   body:{src_ip:'192.0.2.19',action:'deny'},
   syslog_timestamp:'2026-10-12T01:02:03Z'});
  const recipe=await buildReviewableRecipe(source,ready.draft,full);
  expect(recipe.ok).toBe(true);
  if(!recipe.ok)return;
  expect(recipe.recipe.stages[1]).toEqual({op:'dispatch_family',
   families:['json','kv','rfc5424_json','rfc5424_kv'],mode:'strict_prefix'});
  expect(recipe.recipe.nativeVerified).toBe(false);
  for(const secret of ['192.0.2.10','192.0.2.19','203.0.113.4'])
    expect(JSON.stringify(recipe.recipe)).not.toContain(secret);
 });
 it('old backend 7-family capability and untrusted time claims fail closed',()=>{
  const census=analyzeLogEnvelopes(source,'single-line');
  expect(assessEnvelopeCompilation(census,before).status).toBe('COMPILER_UNSUPPORTED');
  const fake=structuredClone(current);
  fake.verification.engineVerified=true as never;
  expect(assessEnvelopeCompilation(census,fake).status).toBe('BACKEND_UNTRUSTED');
 });
 it('never treats malformed or unallowlisted RFC5424 bodies as mixed native-success',()=>{
  // An independently valid CEF record is only accepted if explicitly
  // allowlisted. It is a supported OTHER mixed family, not malformed input.
  const disallowed=createDraft();
  disallowed.format='mixed';
  disallowed.mixedFormats=['json','kv','rfc5424_json','rfc5424_kv'];
  const foreign='<165>1 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.19 act=deny';
  expect(preview(source.split('\n')[0]+'\n'+foreign,disallowed).counts.failures)
    .toBeGreaterThan(0);
  for(const bad of [
   '<165>2 2026-10-12T01:02:03Z edge fw 122 ID - {"src_ip":"192.0.2.19"}',
   '<165>1 2026-10-12T01:02:03 edge fw 122 ID - {"src_ip":"192.0.2.19"}',
   '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - {"src_ip":"192.0.2.19"',
   '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - plaintext unstructured payload',
  ]){
   const report=analyzeLogEnvelopes(source.split('\n')[0]+'\n'+bad,'single-line');
   expect(assessEnvelopeCompilation(report,current).status)
    .not.toBe('DRAFT_COMPILABLE');
  }
 });
});
