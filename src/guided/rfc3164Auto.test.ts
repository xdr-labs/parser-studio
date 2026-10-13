import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe} from './parserRecipeV2';
import type {BackendCapabilities} from './backendCapabilities';

const sample=[
 '<34>Oct  9 14:15:16 edge fw[122]: src_ip=198.51.100.14 dst_port=443 action=deny',
 '<34>Oct  9 14:15:17 edge fw[122]: src_ip=203.0.113.5 dst_port=22 action=allow'
].join('\n');
const cap={
 authoring:{
  extractionFormats:['json','kv','csv','syslog_rfc3164','syslog_rfc5424','cef','leef'],
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],
  rfc3164StrictTaggedMessageSubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',
  rfc3164NativeTimeReconstruction:false
 },
 verification:{engineVerified:false,targetImportVerified:false}
} as unknown as BackendCapabilities;

describe('P0 RFC3164 UI and v0.2 boundary parity',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('auto detects 2 RFC3164+KV lines without asking format or inventing year/zone',async()=>{
  const draft=createDraft(),suite=preview(sample,draft);
  expect(suite.events).toHaveLength(2);
  expect(suite.events.map(x=>x.effectiveFormat)).toEqual(['syslog_rfc3164','syslog_rfc3164']);
  expect(suite.events[0]?.fields).toMatchObject({
   syslog_time_policy:'YEAR_AND_ZONE_UNKNOWN',
   syslog_timestamp:'Oct  9 14:15:16',
   body:{src_ip:'198.51.100.14',dst_port:'443',action:'deny'}
  });
  const ledger=analyzeLogEnvelopes(sample,'single-line');
  const assessment=assessEnvelopeCompilation(ledger,cap);
  expect(assessment).toMatchObject({status:'DRAFT_COMPILABLE',
   format:'syslog_rfc3164',bodyFormat:'kv',nativeVerified:false});
  const prepared=prepareAutoParserDraft(sample,draft,suite,ledger,assessment);
  expect(prepared.ok).toBe(true);
  if(!prepared.ok)return;
  expect(prepared.draft.format).toBe('syslog_rfc3164');
  expect(prepared.draft.syslogBodyFormat).toBe('kv');
  const legacy=toBackendProject(prepared.draft);
  expect(legacy).toMatchObject({ok:true});
  const rerun=preview(sample,prepared.draft);
  expect(rerun.counts).toMatchObject({matched:2,extracted:2,normalized:2,failures:0});
  const recipe=await buildReviewableRecipe(sample,prepared.draft,rerun);
  expect(recipe.ok).toBe(true);
  if(!recipe.ok)return;
  expect(recipe.recipe.sourceFormat).toBe('syslog_rfc3164');
  expect(recipe.recipe.stages.slice(0,3).map(x=>x.op))
   .toEqual(['split_event','unwrap_syslog','parse_kv']);
  expect(recipe.recipe.stages[1]).toEqual({
   op:'unwrap_syslog',version:3164,mode:'strict_header'});
  expect(recipe.recipe.nativeVerified).toBe(false);
  expect(JSON.stringify(recipe.recipe)).not.toContain('198.51.100.14');
 });
 it('fails closed without verified backend capability or before explicit timezone mapping',()=>{
  const draft=createDraft(),ledger=analyzeLogEnvelopes(sample,'single-line');
  expect(assessEnvelopeCompilation(ledger,null).status).toBe('BACKEND_UNAVAILABLE');
  const stale={...cap,authoring:{...cap.authoring,
   rfc3164TimePolicy:'TIMESTAMP_GUESSED'}} as unknown as BackendCapabilities;
  expect(assessEnvelopeCompilation(ledger,stale).status).toBe('BACKEND_UNTRUSTED');
  draft.format='syslog_rfc3164';draft.syslogBodyFormat='kv';
  draft.mappings[0]!.source='syslog_timestamp';
  draft.mappings[0]!.type='timestamp';
  expect(toBackendProject(draft).ok).toBe(false);
 });
 it('does not normalize impossible calendar, malformed quoted fields or multiline as valid RFC3164',()=>{
  const draft=createDraft();
  for(const text of [
   '<34>Apr 31 14:15:16 edge fw: src_ip=192.0.2.1 dst_port=443 action=deny',
   '<34>Oct  9 24:15:16 edge fw: src_ip=192.0.2.1 dst_port=443 action=deny',
   '<34>Oct  9 14:15:16 edge fw: src_ip=192.0.2.1 action="unterminated',
   '<34>Oct  9 14:15:16 edge missing-tag src_ip=192.0.2.1 action=deny',
  ]){
   const ledger=analyzeLogEnvelopes(text,'single-line');
   expect(assessEnvelopeCompilation(ledger,cap).status).not.toBe('DRAFT_COMPILABLE');
   const event=preview(text,draft).events[0];
   expect(event?.status).toBe('fail');
  }
 });
 it('RFC3164 strict CEF and LEEF bodies can be recognized but never claim native/target verified',()=>{
  for(const text of [
   '<165>Oct 12 02:03:04 edge fw[122]: CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
   '<165>Nov 12 02:03:04 edge fw[122]: LEEF:1.0|Synthetic|FW|1|501|src=203.0.113.8\tdstPort=80\tact=deny',
  ]){
   const suite=preview(text,createDraft());
   expect(suite.events[0]?.fields.body).toBeDefined();
   expect(suite.nativeFluentdVerified).toBe(false);
   expect(suite.stellarExportVerified).toBe(false);
   const ledger=analyzeLogEnvelopes(text,'single-line');
   expect(assessEnvelopeCompilation(ledger,cap).status).toBe('DRAFT_COMPILABLE');
  }
 });
});
