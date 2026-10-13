import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe,validateReviewableRecipe} from './parserRecipeV2';
import type {BackendCapabilities} from './backendCapabilities';

const sample=[
 '{"src_ip":"192.0.2.10","dst_port":443,"action":"deny"}',
 'src_ip=198.51.100.8 dst_port=53 action=allow',
 'CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
 'LEEF:1.0|Synthetic|FW|1|501|src=203.0.113.5\tdstPort=80\tact=allow',
].join('\n');
const cap={authoring:{
 extractionFormats:['json','kv','csv','syslog_rfc3164','syslog_rfc5424','cef','leef','mixed'],
 strictMixedSingleLineFamilies:['json','kv','cef','leef'],
 strictMixedRequiresExplicitAllowlist:true},
 verification:{engineVerified:false,targetImportVerified:false}
} as unknown as BackendCapabilities;

describe('P0 strict mixed one-line supported formats, fail closed',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('accounts for all four original families, returns mixed authoring model and native-false staged receipt',async()=>{
  const draft=createDraft();
  const suite=preview(sample,draft);
  expect(suite.events).toHaveLength(4);
  expect(suite.events.map(x=>x.detected.format)).toEqual(['json','kv','cef','leef']);
  const ledger=analyzeLogEnvelopes(sample,'single-line');
  expect(ledger.families).toHaveLength(4);
  const assessed=assessEnvelopeCompilation(ledger,cap);
  expect(assessed).toMatchObject({status:'DRAFT_COMPILABLE',format:'mixed',
   mixedFormats:['cef','json','kv','leef'],nativeVerified:false,targetVerified:false});
  const proposed=prepareAutoParserDraft(sample,draft,suite,ledger,assessed);
  expect(proposed.ok).toBe(true);
  if(!proposed.ok)return;
  expect(proposed.draft.format).toBe('mixed');
  expect(proposed.draft.mixedFormats).toEqual(['cef','json','kv','leef']);
  const translated=toBackendProject(proposed.draft);
  expect(translated).toMatchObject({ok:true});
  if(translated.ok)expect(translated.project.extraction).toMatchObject({
   format:'mixed',mixedFormats:['cef','json','kv','leef']});
  const replay=preview(sample,proposed.draft);
  expect(replay.counts).toMatchObject({total:4,matched:4,extracted:4,
   normalized:4,failures:0});
  const v02=await buildReviewableRecipe(sample,proposed.draft,replay);
  expect(v02.ok).toBe(true);
  if(!v02.ok)return;
  expect(v02.recipe.sourceFormat).toBe('mixed');
  expect(v02.recipe.bodyFormat).toBe('mixed');
  expect(v02.recipe.stages.slice(0,2)).toEqual([
   {op:'split_event',boundary:'single-line'},
   {op:'dispatch_family',families:['cef','json','kv','leef'],mode:'strict_prefix'},
  ]);
  expect(v02.recipe.nativeVerified).toBe(false);
  expect(JSON.stringify(v02.recipe)).not.toContain('192.0.2.10');
 });
 it('rejects forged dispatch recipe, leading whitespace and unapproved branches',async()=>{
  const base=createDraft();
  const source=' '+sample.split('\n')[0]+'\n'+sample.split('\n').slice(1).join('\n');
  const assessment=assessEnvelopeCompilation(analyzeLogEnvelopes(source,'single-line'),cap);
  if(assessment.status==='DRAFT_COMPILABLE'){
    expect(prepareAutoParserDraft(source,base,preview(source,base),
      analyzeLogEnvelopes(source,'single-line'),assessment))
      .toMatchObject({ok:false,reason:'MIXED_OR_UNKNOWN'});
  }
  const generated=prepareAutoParserDraft(sample,base,preview(sample,base),
    analyzeLogEnvelopes(sample,'single-line'),
    assessEnvelopeCompilation(analyzeLogEnvelopes(sample,'single-line'),cap));
  if(!generated.ok)throw new Error('Safe mixed draft expected');
  const draft=generated.draft;
  const record=await buildReviewableRecipe(sample,draft,preview(sample,draft));
  if(!record.ok)throw new Error('Safe staged mixed recipe expected');
  expect(validateReviewableRecipe({...record.recipe,bodyFormat:'json'})).toBe(false);
  for(const change of [
    {families:['json','json'],mode:'strict_prefix'},
    {families:['json','kv','cef','leef','csv'],mode:'strict_prefix'},
    {families:['json','kv','cef','leef'],mode:'allow_fallback'},
  ]){
    expect(validateReviewableRecipe({...record.recipe,stages:[
      record.recipe.stages[0],{op:'dispatch_family',...change},
      ...record.recipe.stages.slice(2),
    ]})).toBe(false);
  }
 });
 it('cannot upgrade malformed, unrecognized, CSV, RFC3164 or RFC5424 into mixed-success',()=>{
  for(const extra of [
   'PRIVATE_UNSUPPORTED_EVENT no match',
   'allow,192.0.2.10,443',
   '<34>Oct  9 14:15:16 edge fw[122]: action=allow src_ip=192.0.2.10',
   '<34>1 2026-10-12T00:00:00Z edge fw 12 ID - action=deny src_ip=192.0.2.10',
   '{"unclosed":',
  ]){
   const source=sample+'\n'+extra;
   const ledger=analyzeLogEnvelopes(source,'single-line');
   expect(assessEnvelopeCompilation(ledger,cap).status).not.toBe('DRAFT_COMPILABLE');
  }
 });
 it('rejects old backends, forged allowlists, spoofed native flags and changed source',()=>{
  const report=analyzeLogEnvelopes(sample,'single-line');
  expect(assessEnvelopeCompilation(report,null).status).toBe('BACKEND_UNAVAILABLE');
  expect(assessEnvelopeCompilation(report,{...cap,authoring:{
   ...cap.authoring,strictMixedRequiresExplicitAllowlist:false
  }} as unknown as BackendCapabilities).status).toBe('BACKEND_UNTRUSTED');
  expect(assessEnvelopeCompilation(report,{...cap,authoring:{
   ...cap.authoring,extractionFormats:['json','kv','cef','leef']
  }}).status).not.toBe('DRAFT_COMPILABLE');
  const data=preview(sample,createDraft());
  const verdict=assessEnvelopeCompilation(report,cap);
  data.nativeFluentdVerified=true as false;
  expect(prepareAutoParserDraft(sample,createDraft(),data,report,verdict))
   .toMatchObject({ok:false,reason:'UNTRUSTED_PREVIEW'});
 });
});
