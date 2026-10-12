import {describe,it,expect,beforeEach,afterEach,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildReviewableRecipe} from './parserRecipeV2';
import {createPrivacySafeAIPrompt,importReviewOnlyAIRecipe,
 proposeV01FieldMappingFromAI} from './aiRecipeExchange';

const source=[
 '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"name":"PRIVATE_ACCOUNT"}',
 '{"action":"deny","src_ip":"203.0.113.4","dst_port":22,"name":"SECRET_USER"}',
].join('\n');
const draft={...createDraft(),format:'json' as const};
const suite=()=>preview(source,draft);

describe('P1-AP6 explicit local AI exchange, fail-closed',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('generates a copyable schema-only prompt with no sample values, credentials, or automatic egress',async()=>{
  const r=await createPrivacySafeAIPrompt(source,draft,suite());
  expect(r).toMatchObject({ok:true,sourceCount:2,rawLogsIncluded:false,automaticUpload:false});
  if(!r.ok)return;
  expect(r.sampleSha256).toMatch(/^[a-f0-9]{64}$/);
  for(const secret of ['198.51.100.10','203.0.113.4','SECRET_USER','PRIVATE_ACCOUNT','src_ip'])
   expect(r.prompt).not.toContain(secret);
  expect(r.prompt).toContain('REVIEW_ONLY');
 });
 it('still offers a privacy-safe diagnostic prompt for unknown logs and untouched novice auto mode',async()=>{
  const auto=createDraft();
  const unknown='PRIVATE_CUSTOMER_EVENT alpha beta\nPRIVATE_LOGIN failed user';
  const result=await createPrivacySafeAIPrompt(unknown,auto,preview(unknown,auto));
  expect(result).toMatchObject({ok:true,currentProjectImportReady:false,
   rawLogsIncluded:false,automaticUpload:false});
  if(!result.ok)return;
  expect(result.prompt).toContain('plain-English diagnostic');
  expect(result.prompt).not.toContain('PRIVATE_CUSTOMER_EVENT');
  expect(result.prompt).not.toContain('PRIVATE_LOGIN');
 });
 it('accepts an exact bounded v0.2 structure only as a review, with no automatic parser compiler claim',async()=>{
  const built=await buildReviewableRecipe(source,draft,suite());
  expect(built.ok).toBe(true);
  if(!built.ok)return;
  const value=await importReviewOnlyAIRecipe(JSON.stringify(built.recipe),source,draft,suite());
  expect(value).toMatchObject({ok:true,report:{status:'REVIEW_ONLY',
   changedStageCount:0,addedMappings:0,removedMappings:0,
   userApprovalRequired:true,backendCompilerAvailable:false}});
  if(value.ok)expect(JSON.stringify(value.report)).not.toContain('PRIVATE_ACCOUNT');
 });
 it('rejects forged native success, dangerous operator and extraneous keys',async()=>{
  const built=await buildReviewableRecipe(source,draft,suite());
  if(!built.ok)throw new Error('Expected supported recipe');
  for(const changed of [
   {...built.recipe,nativeVerified:true},
   {...built.recipe,targetVerified:true},
   {...built.recipe,script:'eval("unsafe")'},
   {...built.recipe,stages:[...built.recipe.stages.slice(0,-1),
     {op:'eval_ruby',code:'system("curl")'},built.recipe.stages.at(-1)]},
  ])expect(await importReviewOnlyAIRecipe(JSON.stringify(changed),source,draft,suite()))
   .toMatchObject({ok:false,reason:'UNTRUSTED_RECIPE'});
 });
 it('permits exactly one new safe AI field mapping to become a non-applied v0.1 repair candidate',async()=>{
  const original=await buildReviewableRecipe(source,draft,suite());
  if(!original.ok)throw new Error('Expected supported original');
  const stages=[...original.recipe.stages];
  stages.splice(stages.findIndex(s=>s.op==='classify'),0,
   {op:'map_field',source:'name',target:'custom.account_label',
    data_type:'string',group:'vendor_fields'});
  const changed={...original.recipe,stages};
  const imported=await importReviewOnlyAIRecipe(JSON.stringify(changed),source,draft,suite());
  expect(imported).toMatchObject({ok:true,report:{addedMappings:1}});
  const proposal=proposeV01FieldMappingFromAI(imported,source,draft,suite());
  expect(proposal).toMatchObject({ok:true,source:'name',target:'custom.account_label',
   approvalRequired:true,backendCompilerVerified:false});
  expect(draft.mappings).toHaveLength(3);
  if(!proposal.ok)return;
  expect(proposal.candidate.mappings).toHaveLength(4);
  const unavailable={...original.recipe,stages:stages.map(s=>
   s.op==='map_field'&&s.source==='name'?{...s,source:'missing_field'}:s)};
  const unsupported=await importReviewOnlyAIRecipe(JSON.stringify(unavailable),source,draft,suite());
  expect(proposeV01FieldMappingFromAI(unsupported,source,draft,suite()))
   .toMatchObject({ok:false,reason:'SOURCE_NOT_PRESENT'});
  const changedClass=stages.map(s=>s.op==='classify'?{...s,defaultIndex:'threat' as const}:s);
  const other=await importReviewOnlyAIRecipe(JSON.stringify({...original.recipe,
   stages:changedClass}),source,draft,suite());
  expect(proposeV01FieldMappingFromAI(other,source,draft,suite()))
   .toMatchObject({ok:false,reason:'UNSUPPORTED_OPERATOR_CHANGE'});
 });
 it('enforces the exact source identity, sample count, valid format, and user-edited draft',async()=>{
  const built=await buildReviewableRecipe(source,draft,suite());
  if(!built.ok)throw new Error('Expected supported recipe');
  const recipe=JSON.stringify(built.recipe);
  expect(await importReviewOnlyAIRecipe(recipe,source+'\nnew',draft,suite()))
   .toMatchObject({ok:false,reason:'UNTRUSTED_PREVIEW'});
  expect(await importReviewOnlyAIRecipe(JSON.stringify({...built.recipe,
   sample:{...built.recipe.sample,sha256:'a'.repeat(64)}}),source,draft,suite()))
   .toMatchObject({ok:false,reason:'SOURCE_IDENTITY_MISMATCH'});
  expect(await importReviewOnlyAIRecipe(JSON.stringify({...built.recipe,bodyFormat:'kv'}),source,draft,suite()))
   .toMatchObject({ok:false,reason:'UNTRUSTED_RECIPE'});
  expect(await importReviewOnlyAIRecipe('{not json',source,draft,suite()))
   .toMatchObject({ok:false,reason:'INVALID_JSON'});
  expect(await importReviewOnlyAIRecipe('X'.repeat(40000),source,draft,suite()))
   .toMatchObject({ok:false,reason:'INPUT_TOO_LARGE'});
 });
});
