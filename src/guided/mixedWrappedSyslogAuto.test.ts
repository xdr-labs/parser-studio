import {describe,it,beforeEach,afterEach,expect,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe} from './parserRecipeV2';
import type {BackendCapabilities} from './backendCapabilities';

const source=[
 '{"src_ip":"192.0.2.10","dst_port":443,"action":"deny"}',
 '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
 '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^dstPort=80^act=allow',
].join('\n');
const oldCap={authoring:{
 extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc5424'],
 strictMixedRequiresExplicitAllowlist:true,
 strictMixedSingleLineFamilies:['json','kv','cef','leef'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const newCap={...oldCap,authoring:{
 ...oldCap.authoring,
 strictMixedSingleLineFamilies:[
  'json','kv','cef','leef','rfc5424_cef','rfc5424_leef',
 ] as BackendCapabilities['authoring']['strictMixedSingleLineFamilies'],
}} as BackendCapabilities;
describe('P0 mixed RFC5424-wrapped CEF/LEEF and standalone JSON in beginner path',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('preserves all source lines and builds a strict reviewed mixed Ruby/CONF project without guessing formats',async()=>{
  const draft=createDraft(),suite=preview(source,draft),ledger=analyzeLogEnvelopes(source,'single-line');
  expect(ledger).toMatchObject({status:'READY',sourceCount:3,accounted:3,unsupported:0});
  expect(ledger.families.map(x=>x.envelope+':'+x.body).sort()).toEqual([
   'none:json','rfc5424:cef','rfc5424:leef',
  ]);
  const assessed=assessEnvelopeCompilation(ledger,newCap);
  expect(assessed).toMatchObject({
   status:'DRAFT_COMPILABLE',format:'mixed',
   mixedFormats:['json','rfc5424_cef','rfc5424_leef'],
   nativeVerified:false,targetVerified:false,
  });
  const prepared=prepareAutoParserDraft(source,draft,suite,ledger,assessed);
  expect(prepared.ok).toBe(true);
  if(!prepared.ok)return;
  expect(prepared.draft.guided?.receiver.port).toBeGreaterThanOrEqual(6800);
  expect(prepared.draft.mixedFormats).toEqual(['json','rfc5424_cef','rfc5424_leef']);
  expect(toBackendProject(prepared.draft)).toMatchObject({
   ok:true,project:{extraction:{
    format:'mixed',mixedFormats:['json','rfc5424_cef','rfc5424_leef'],
   }},
  });
  const regression=preview(source,prepared.draft);
  expect(regression.counts).toMatchObject({
   total:3,matched:3,extracted:3,normalized:3,failures:0,
  });
  expect(regression.events[1]?.fields).toMatchObject({
   body:{src:'192.0.2.11',dpt:'443',act:'deny'},
  });
  const recipe=await buildReviewableRecipe(source,prepared.draft,regression);
  expect(recipe.ok).toBe(true);
  if(!recipe.ok)return;
  expect(recipe.recipe.stages[1]).toEqual({
   op:'dispatch_family',families:['json','rfc5424_cef','rfc5424_leef'],mode:'strict_prefix',
  });
  for(const raw of ['192.0.2.10','192.0.2.11','203.0.113.8'])
   expect(JSON.stringify(recipe.recipe)).not.toContain(raw);
 });
 it('old backends, malformed wrapped versions and unapproved wrapped families cannot silently pass',()=>{
  const draft=createDraft(),suite=preview(source,draft),ledger=analyzeLogEnvelopes(source,'single-line');
  expect(assessEnvelopeCompilation(ledger,oldCap).status).toBe('COMPILER_UNSUPPORTED');
  for(const raw of [
   '<165>2 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
   '<165>1 2026-10-12T01:02:03 edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
   '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - action=deny',
   '<34>Oct  9 14:15:16 edge fw[122]: src=192.0.2.1',
  ]){
   const candidate=source.split('\n')[0]+'\n'+raw;
   const report=analyzeLogEnvelopes(candidate,'single-line');
   expect(assessEnvelopeCompilation(report,newCap).status).not.toBe('DRAFT_COMPILABLE');
  }
  expect(suite.nativeFluentdVerified).toBe(false);
  expect(suite.stellarExportVerified).toBe(false);
 });
});
