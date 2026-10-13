import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe} from './parserRecipeV2';
import type {BackendCapabilities} from './backendCapabilities';

const samples=[
 '{"src_ip":"192.0.2.10","action":"deny"}',
 'src_ip=198.51.100.8 action=allow',
 '<34>Oct  9 14:15:16 edge fw[122]: src_ip=192.0.2.17 action=deny',
].join('\n');
const baseCap={authoring:{
 extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
 strictMixedRequiresExplicitAllowlist:true,
 strictMixedSingleLineFamilies:['json','kv','cef','leef','rfc5424_cef','rfc5424_leef'],
 rfc3164StrictTaggedMessageSubset:true,
 rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',
 rfc3164NativeTimeReconstruction:false,
 rfc3164BodyFormats:['raw','json','kv','cef','leef'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const newCap={...baseCap,authoring:{
 ...baseCap.authoring,
 strictMixedSingleLineFamilies:[
  'json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv',
 ] as BackendCapabilities['authoring']['strictMixedSingleLineFamilies'],
}} as BackendCapabilities;
describe('P0 RFC3164 TAG KV mixed beginner+v0.2 native-reviewed bound',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('accounts for all three lines and builds a review-only strict staged draft',async()=>{
  const draft=createDraft(),first=preview(samples,draft);
  const ledger=analyzeLogEnvelopes(samples,'single-line');
  expect(ledger).toMatchObject({sourceCount:3,accounted:3,unsupported:0});
  expect(ledger.families.map(f=>f.envelope+':'+f.body).sort())
    .toEqual(['none:json','none:kv','rfc3164:kv']);
  expect(ledger.events[2]).toMatchObject({timePolicy:'YEAR_AND_ZONE_UNKNOWN'});
  const assessed=assessEnvelopeCompilation(ledger,newCap);
  expect(assessed).toMatchObject({status:'DRAFT_COMPILABLE',
   format:'mixed',mixedFormats:['json','kv','rfc3164_kv'],
   nativeVerified:false,targetVerified:false});
  const prepared=prepareAutoParserDraft(samples,draft,first,ledger,assessed);
  expect(prepared.ok).toBe(true);
  if(!prepared.ok)return;
  expect(prepared.draft.mixedFormats).toEqual(['json','kv','rfc3164_kv']);
  expect(prepared.draft.guided?.receiver.port).toBeGreaterThanOrEqual(6800);
  const post=preview(samples,prepared.draft);
  expect(post.counts).toMatchObject({
   total:3,matched:3,extracted:3,normalized:3,failures:0,
  });
  expect(post.events[2]?.fields).toMatchObject({
   syslog_time_policy:'YEAR_AND_ZONE_UNKNOWN',
   body:{src_ip:'192.0.2.17',action:'deny'},
  });
  const backend=toBackendProject(prepared.draft);
  expect(backend).toMatchObject({ok:true,project:{extraction:{
   format:'mixed',mixedFormats:['json','kv','rfc3164_kv']}}});
  const recipe=await buildReviewableRecipe(samples,prepared.draft,post);
  expect(recipe.ok).toBe(true);
  if(!recipe.ok)return;
  expect(recipe.recipe.stages[1]).toEqual({
   op:'dispatch_family',families:['json','kv','rfc3164_kv'],mode:'strict_prefix'});
  expect(recipe.recipe.nativeVerified).toBe(false);
  for(const sample of ['192.0.2.10','198.51.100.8','192.0.2.17'])
   expect(JSON.stringify(recipe.recipe)).not.toContain(sample);
 });
 it('does not compile against older 4/6-family backends or infer RFC3164 timestamp',()=>{
  const report=analyzeLogEnvelopes(samples,'single-line');
  expect(assessEnvelopeCompilation(report,baseCap).status)
   .toBe('COMPILER_UNSUPPORTED');
  const badCap=structuredClone(newCap);
  badCap.authoring.rfc3164TimePolicy='GUESSED' as never;
  expect(assessEnvelopeCompilation(report,badCap).status).not.toBe('DRAFT_COMPILABLE');
  const p=createDraft();
  p.format='mixed';p.mixedFormats=['json','kv','rfc3164_kv'];
  p.mappings=[{id:'year',source:'syslog_timestamp',
   target:'custom.guessed_time',type:'timestamp'}];
  expect(toBackendProject(p).ok).toBe(false);
 });
 it('strict RFC3164 rejects malformed headers, unsupported bodies and multiline',()=>{
  for(const bad of [
   '<34>Bad  9 14:15:16 edge fw[122]: src_ip=192.0.2.17 action=deny',
   '<192>Oct  9 14:15:16 edge fw[122]: src_ip=192.0.2.17 action=deny',
   '<34>Oct  9 14:15:16 edge fw[122]: CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.17 act=deny',
   '<34>Feb 30 14:15:16 edge fw[122]: src_ip=192.0.2.17 action=deny',
   '<34>Oct  9 14:15:16 edge fw[122]: src_ip="192.0.2.17 action=deny',
  ]){
   const ledger=analyzeLogEnvelopes(samples.split('\n')[0]+'\n'+bad,'single-line');
   expect(assessEnvelopeCompilation(ledger,newCap).status)
    .not.toBe('DRAFT_COMPILABLE');
  }
 });
});
