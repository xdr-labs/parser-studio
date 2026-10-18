import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview,detectFormat} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe} from './parserRecipeV2';
import type {BackendCapabilities} from './backendCapabilities';

const source=[
 '{"src_ip":"192.0.2.10","action":"deny","dst_port":443}',
 'src_ip=198.51.100.8 action=allow dst_port=443',
 '192.0.2.17;deny;22',
 '"203.0.113.19";allow;8443',
].join('\n');
const oldCapability={authoring:{
 extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
 strictMixedRequiresExplicitAllowlist:true,
 strictMixedSingleLineFamilies:[
  'json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv',
  'rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const cap={...oldCapability,authoring:{
 ...oldCapability.authoring,
 strictMixedSingleLineFamilies:[
  ...(oldCapability.authoring.strictMixedSingleLineFamilies??[]),'csv',
 ] as BackendCapabilities['authoring']['strictMixedSingleLineFamilies'],
}} as BackendCapabilities;
describe('P1 strict reviewed CSV mixed family is not auto-inferred without columns',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('locally identifies semicolon CSV without inventing column names',()=>{
  expect(detectFormat('192.0.2.17;deny;22').format).toBe('csv');
  expect(detectFormat('192.0.2.17,deny,22').format).toBe('csv');
  expect(detectFormat('192.0.2.17\tdeny\t22').format).toBe('csv');
 });
 it('accounting covers all four JSON/KV/semicolon CSV samples and strict v0.2 pair',async()=>{
  const draft=createDraft();
  draft.csvColumns='src_ip,action,dst_port';
  draft.csvDelimiter=';';
  const initial=preview(source,draft);
  const ledger=analyzeLogEnvelopes(source,'single-line');
  expect(ledger).toMatchObject({sourceCount:4,accounted:4,unsupported:0,complete:true});
  expect(ledger.families.map(f=>f.envelope+':'+f.body).sort())
   .toEqual(['none:csv','none:json','none:kv']);
  expect(assessEnvelopeCompilation(ledger,oldCapability).status).toBe('COMPILER_UNSUPPORTED');
  const assessed=assessEnvelopeCompilation(ledger,cap);
  expect(assessed).toMatchObject({status:'DRAFT_COMPILABLE',format:'mixed',
    mixedFormats:['csv','json','kv'],nativeVerified:false,targetVerified:false});
  const prepared=prepareAutoParserDraft(source,draft,initial,ledger,assessed);
  expect(prepared.ok).toBe(true);
  if(!prepared.ok)return;
  const result=preview(source,prepared.draft);
  expect(result.counts).toMatchObject({total:4,matched:4,normalized:4,failures:0});
  const project=toBackendProject(prepared.draft);
  expect(project).toMatchObject({ok:true,project:{extraction:{
    format:'mixed',mixedFormats:['csv','json','kv'],
    csvColumns:['src_ip','action','dst_port'],csvDelimiter:';'
  }}});
  const staged=await buildReviewableRecipe(source,prepared.draft,result);
  expect(staged.ok).toBe(true);
  if(!staged.ok)return;
  expect(staged.recipe.stages[1]).toEqual({
    op:'dispatch_family',families:['csv','json','kv'],mode:'strict_prefix'
  });
  for(const raw of ['192.0.2.10','203.0.113.19'])
    expect(JSON.stringify(staged.recipe)).not.toContain(raw);
 });
 it('rejects missing CSV names, unknown bodies and unreviewed schemas',()=>{
  const draft=createDraft();draft.format='mixed';
  draft.mixedFormats=['json','kv','csv'];
  draft.csvDelimiter=';';
  draft.csvColumns='';
  expect(toBackendProject(draft).ok).toBe(false);
  draft.csvColumns='src_ip,action,dst_port';
  expect(toBackendProject(draft).ok).toBe(true);
  for(const bad of [
   '192.0.2.17;deny',
   '192.0.2.17;deny;22;extra',
   '"192.0.2.17;deny;22',
   '192.0.2.17,deny,22',
  ]){
   expect(preview(bad,draft).counts.failures).toBeGreaterThan(0);
  }
 });
});
