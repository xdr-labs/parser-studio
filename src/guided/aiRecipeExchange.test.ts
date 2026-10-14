import {describe,it,expect,beforeEach,afterEach,vi} from 'vitest';
import {createHash,webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildReviewableRecipe} from './parserRecipeV2';
import {toBackendProject} from './backendAdapter';
import {createPrivacySafeAIPrompt,importRecoveryAIRecipe,importReviewOnlyAIRecipe,
 proposeV01FieldMappingFromAI,proposeV01MappingCorrectionFromAI,proposeV01RecoveryParserFromAI} from './aiRecipeExchange';

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
  const translated=toBackendProject(proposal.candidate);
  expect(translated.ok).toBe(true);
  if(translated.ok)expect(translated.project.normalization.vendorFields.name)
   .toEqual({normalized_name:'custom.account_label',data_type:'string'});
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
 it('corrects exactly one existing mapping while preserving parser grammar and unrelated rules',async()=>{
  const original=await buildReviewableRecipe(source,draft,suite());
  if(!original.ok)throw new Error('Expected supported original');
  const stages=original.recipe.stages.map(stage=>{
   if(stage.op==='map_field'&&stage.source==='src_ip')return {...stage,target:'custom.source_address'};
   if(stage.op==='cast_type'&&stage.target==='custom.source_ip')return {...stage,target:'custom.source_address'};
   return stage;
  });
  const imported=await importReviewOnlyAIRecipe(JSON.stringify({...original.recipe,stages}),source,draft,suite());
  expect(imported).toMatchObject({ok:true,report:{mode:'BASELINE_EDIT',addedMappings:1,removedMappings:1}});
  expect(proposeV01FieldMappingFromAI(imported,source,draft,suite()))
   .toMatchObject({ok:false,reason:'NO_SINGLE_SAFE_MAPPING'});
  const corrected=proposeV01MappingCorrectionFromAI(imported,source,draft,suite());
  expect(corrected).toMatchObject({ok:true,mappingId:'source-ip',replacement:'ONE_MAPPING'});
  if(!corrected.ok)return;
  expect(corrected.candidate.mappings).toEqual([
   {...draft.mappings[0]!,target:'custom.source_address'},draft.mappings[1],draft.mappings[2],
  ]);
  const local=preview(source,corrected.candidate);
  expect(local.counts).toMatchObject({total:2,matched:2,extracted:2,normalized:2,failures:0});
  const exact=await buildReviewableRecipe(source,corrected.candidate,local);
  expect(exact.ok).toBe(true);
  if(exact.ok)expect(exact.recipe).toEqual({...original.recipe,stages});
 });
 it('recovers an auto-RAW two-column CSV into a fully reviewable compiler-supported parser',async()=>{
  const raw='allow,198.51.100.10\ndeny,203.0.113.4';
  const auto=createDraft(),baseline=preview(raw,auto);
  expect(baseline.counts.extracted).toBe(0);
  const hash=createHash('sha256').update(raw).digest('hex');
  const recovery={
   contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
   projectId:'draft-demo_firewall',sourceFormat:'csv',bodyFormat:'csv',
   sample:{sha256:hash,events:2},nativeVerified:false,targetVerified:false,
   stages:[
    {op:'split_event',boundary:'single-line'},
    {op:'parse_csv',columns:['action','src_ip'],delimiter:','},
    {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
    {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
    {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
    {op:'classify',defaultIndex:'syslog',rules:[]},
    {op:'fallback_unparsed',mode:'retain_unparsed'},
   ],
  };
  expect(await importReviewOnlyAIRecipe(JSON.stringify(recovery),raw,auto,baseline))
   .toMatchObject({ok:false,reason:'CURRENT_RECIPE_UNAVAILABLE'});
  const imported=await importRecoveryAIRecipe(JSON.stringify(recovery),raw,auto,baseline);
  expect(imported).toMatchObject({ok:true,report:{mode:'FULL_RECOVERY',addedMappings:2}});
  const proposal=proposeV01RecoveryParserFromAI(imported,auto);
  expect(proposal).toMatchObject({ok:true,replacement:'FULL_PARSER',approvalRequired:true});
  if(!proposal.ok)return;
  expect(proposal.candidate).toMatchObject({format:'csv',csvColumns:'action,src_ip'});
  const recovered=preview(raw,proposal.candidate);
  expect(recovered.counts).toMatchObject({total:2,matched:2,extracted:2,normalized:2,failures:0});
  const rebuilt=await buildReviewableRecipe(raw,proposal.candidate,recovered);
  expect(rebuilt.ok).toBe(true);
  if(rebuilt.ok)expect(rebuilt.recipe).toEqual(recovery);
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
