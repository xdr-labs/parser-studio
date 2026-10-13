import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
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
 '<165>Oct 12 02:03:04 edge fw[122]: CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
 '<165>Nov 12 02:03:04 edge fw[122]: LEEF:1.0|Synthetic|FW|1|501|src=203.0.113.8\tdstPort=80\tact=allow',
].join('\n');
const oldCap={authoring:{
 extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
 strictMixedRequiresExplicitAllowlist:true,
 strictMixedSingleLineFamilies:[
  'json','kv','cef','leef','rfc5424_cef','rfc5424_leef',
  'rfc3164_kv','rfc5424_json','rfc5424_kv',
 ],
 rfc3164StrictTaggedMessageSubset:true,
 rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',
 rfc3164NativeTimeReconstruction:false,
 rfc3164BodyFormats:['raw','json','kv','cef','leef'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const newCap={...oldCap,authoring:{...oldCap.authoring,
 strictMixedSingleLineFamilies:[
  'json','kv','cef','leef','rfc5424_cef','rfc5424_leef',
  'rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef',
 ] as BackendCapabilities['authoring']['strictMixedSingleLineFamilies'],
}} as BackendCapabilities;

describe('P0 strict RFC3164 CEF/LEEF mixed beginner and reviewed v0.2 pair',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('accounts for four events and preserves yearless RFC3164 without format guessing',async()=>{
  const draft=createDraft(),initial=preview(source,draft);
  const ledger=analyzeLogEnvelopes(source,'single-line');
  expect(ledger).toMatchObject({sourceCount:4,accounted:4,unsupported:0});
  expect(ledger.families.map(f=>f.envelope+':'+f.body).sort())
   .toEqual(['none:json','none:kv','rfc3164:cef','rfc3164:leef']);
  expect(ledger.events[2]?.timePolicy).toBe('YEAR_AND_ZONE_UNKNOWN');
  expect(ledger.events[3]?.timePolicy).toBe('YEAR_AND_ZONE_UNKNOWN');
  const assessed=assessEnvelopeCompilation(ledger,newCap);
  expect(assessed).toMatchObject({status:'DRAFT_COMPILABLE',format:'mixed',
   mixedFormats:['json','kv','rfc3164_cef','rfc3164_leef'],
   nativeVerified:false,targetVerified:false});
  const prepared=prepareAutoParserDraft(source,draft,initial,ledger,assessed);
  expect(prepared.ok).toBe(true);
  if(!prepared.ok)return;
  expect(prepared.draft.guided?.receiver.port).toBeGreaterThanOrEqual(6800);
  const report=preview(source,prepared.draft);
  expect(report.counts).toMatchObject({total:4,matched:4,extracted:4,normalized:4,failures:0});
  expect(report.events[2]?.fields).toMatchObject({
   syslog_time_policy:'YEAR_AND_ZONE_UNKNOWN',body:{src:'192.0.2.11',act:'deny'}});
  const backend=toBackendProject(prepared.draft);
  expect(backend).toMatchObject({ok:true,project:{extraction:{
   format:'mixed',mixedFormats:['json','kv','rfc3164_cef','rfc3164_leef']}}});
  const recipe=await buildReviewableRecipe(source,prepared.draft,report);
  expect(recipe.ok).toBe(true);
  if(!recipe.ok)return;
  expect(recipe.recipe.stages[1]).toEqual({op:'dispatch_family',
   families:['json','kv','rfc3164_cef','rfc3164_leef'],mode:'strict_prefix'});
  expect(recipe.recipe.nativeVerified).toBe(false);
  for(const raw of ['192.0.2.10','192.0.2.11','203.0.113.8'])
   expect(JSON.stringify(recipe.recipe)).not.toContain(raw);
 });
 it('older backend refuses new branches and yearless timestamp cannot become date',()=>{
  const ledger=analyzeLogEnvelopes(source,'single-line');
  expect(assessEnvelopeCompilation(ledger,oldCap).status).toBe('COMPILER_UNSUPPORTED');
  const draft=createDraft();draft.format='mixed';
  draft.mixedFormats=['json','kv','rfc3164_cef','rfc3164_leef'];
  draft.mappings=[{id:'implied-year',source:'syslog_timestamp',
   target:'custom.guessed_timestamp',type:'timestamp'}];
  expect(toBackendProject(draft).ok).toBe(false);
 });
 it('malformed, unknown and unselected RFC3164 sub-families cannot silently pass',()=>{
  const allow=createDraft();allow.format='mixed';
  allow.mixedFormats=['json','kv','rfc3164_cef','rfc3164_leef'];
  const validButUnselected='<165>Oct 12 02:03:04 edge fw[122]: src_ip=192.0.2.11 action=deny';
  expect(preview(source.split('\n')[0]+'\n'+validButUnselected,allow).counts.failures)
   .toBeGreaterThan(0);
  for(const bad of [
   '<165>Bad 12 02:03:04 edge fw[122]: CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 act=deny',
   '<165>Oct 12 02:03:04 edge fw[122]: CEF:2|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 act=deny',
   '<165>Oct 12 02:03:04 edge fw[122]: plaintext unstructured payload',
  ]){
   const report=analyzeLogEnvelopes(source.split('\n')[0]+'\n'+bad,'single-line');
   expect(assessEnvelopeCompilation(report,newCap).status).not.toBe('DRAFT_COMPILABLE');
  }
 });
});
