/** P1-AP6 offline, user-directed AI prompt and strict REVIEW_ONLY import.
 * No provider calls, automatic raw sample export, Ruby/Grok/JSONata execution.
 * A bounded named-capture parse_regex stage may be reviewed under the same explicit approval gates.
 */
import type {ParserDraft,SuiteResult} from '../model';
import {MAX_DATASET_BYTES,MAX_EVENTS,splitEvents} from '../parser';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {buildReviewableRecipe,validateReviewableRecipe,
 type ParserRecipeV2,type ReviewStage} from './parserRecipeV2';
import {toBackendProject} from './backendAdapter';
import {lookupFieldValue} from '../fieldPaths';
import {defaultGuidedOptions} from './contract';
import {sha256Utf8Hex} from '../sha256';

const MAX_RECIPE_BYTES=32*1024;
export type AIExchangeReason='SOURCE_LIMIT'|'UNTRUSTED_PREVIEW'|
 'PROJECT_UNSUPPORTED'|'CURRENT_RECIPE_UNAVAILABLE'|'INPUT_TOO_LARGE'|
 'INVALID_JSON'|'UNTRUSTED_RECIPE'|'SOURCE_IDENTITY_MISMATCH'|
 'FORMAT_MISMATCH'|'UNSUPPORTED_OPERATION';
export type AIPromptResult=
 | {ok:true;prompt:string;sampleSha256:string;sourceCount:number;
     currentProjectImportReady:boolean;rawLogsIncluded:false;automaticUpload:false}
 | {ok:false;reason:AIExchangeReason};
export type AIImportResult=
 | {ok:true;candidate:ParserRecipeV2;baseline:ParserRecipeV2|null;
     report:{contract:'auto-parser.ai-import-review.v0.1';
       status:'REVIEW_ONLY';mode:'BASELINE_EDIT'|'FULL_RECOVERY';changedStageCount:number;addedMappings:number;
       removedMappings:number;sampleEvents:number;backendCompilerAvailable:false;
       userApprovalRequired:true;rawLogsIncluded:false}}
 | {ok:false;reason:AIExchangeReason};

async function digest(text:string):Promise<string>{return sha256Utf8Hex(text);}
function verified(source:string,suite:SuiteResult):boolean{
 if(typeof source!=='string'||!source.trim()||
  new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES||
  !suite||suite.engine!=='browser-preview'||suite.nativeFluentdVerified!==false||
  suite.stellarExportVerified!==false||!Array.isArray(suite.events))return false;
 const records=splitEvents(source,'single-line',MAX_EVENTS+1);
 return records.length>=1&&records.length<=MAX_EVENTS&&
  suite.counts.total===records.length&&suite.events.length===records.length&&
  records.every((record,i)=>record.raw===suite.events[i]?.raw&&
   record.line===suite.events[i]?.line);
}
/** Fixed structure and digest only; deliberately no raw samples, fields or values. */
export async function createPrivacySafeAIPrompt(
 source:string,draft:ParserDraft,suite:SuiteResult,
):Promise<AIPromptResult>{
 if(!verified(source,suite))return {ok:false,reason:'UNTRUSTED_PREVIEW'};
 const projected=toBackendProject(draft);
 const ledger=analyzeLogEnvelopes(source,'single-line');
 if(ledger.status!=='READY'||ledger.accounted!==suite.events.length)
  return {ok:false,reason:'SOURCE_LIMIT'};
 const hash=await digest(source);
 const families=ledger.families.map(({envelope,body,count})=>({envelope,body,count}));
 const meta={projectId:projected.ok?projected.project.projectId:null,
  currentProjectImportReady:projected.ok,sourceCount:ledger.sourceCount,
  sourceHash:hash,families,unsupported:ledger.unsupported};
 const prompt=[
  'Create a conservative Parser Studio v0.2 REVIEW_ONLY JSON recipe proposal.',
  'The JSON object MUST contain only these root keys:',
  'contract, schemaRevision, compilerMode, projectId, sourceFormat, bodyFormat, sample, stages, nativeVerified, targetVerified.',
  'Use contract parser-studio.recipe.v0.2; schemaRevision 0.2; compilerMode REVIEW_ONLY; nativeVerified=false; targetVerified=false.',
  'If projectId is present, it must match the metadata below; sample must be {sha256: sourceHash, events: sourceCount}.',
  'If projectId is null, the current draft is not backend-compatible: provide a plain-English diagnostic and request reviewed redacted examples instead of inventing a valid recipe.',
  'Allow only stages: split_event(single-line), optional unwrap_syslog(version 1, strict_header),',
  'one parse_json/parse_kv/parse_cef/parse_leef/parse_csv/parse_generic_structural or bounded parse_regex, map_field, adjacent cast_type, bounded split_field/merge_fields, classify, fallback_unparsed.',
  'parse_generic_structural is allowed only for Parser Studio Generic Structural Ultra source-complete recovery and uses the fixed bounded compiler grammar; do not invent vendor grammar.',
  'parse_regex is allowed only for a <=256-character named-capture pattern without backreferences, lookbehind, unsafe nested repetition, or any {m,n} repetition bound above 128.',
  'Never provide Ruby, Grok, JSONata execution, arbitrary code, credentials, API requests or deployment instructions.',
  'Refuse to assert a supported grammar when family metadata is insufficient or mixed.',
  'All rules require local user review. Native Fluentd and Stellar target import are NOT VERIFIED.',
  'Only count, family and digest metadata follow. No raw logs or field values have been included:',
  JSON.stringify(meta),
  'If you need more context, ASK for explicitly user-approved, manually redacted example records; do not invent semantics.',
 ].join('\n');
 return {ok:true,prompt,sampleSha256:hash,sourceCount:ledger.sourceCount,
  currentProjectImportReady:projected.ok,rawLogsIncluded:false,automaticUpload:false};
}
const mapping=(stages:ReviewStage[])=>stages.filter(
 (x):x is Extract<ReviewStage,{op:'map_field'}>=>x.op==='map_field');
const enrichment=(stages:ReviewStage[])=>stages.filter(
 (x):x is Extract<ReviewStage,{op:'split_field'|'merge_fields'}>=>x.op==='split_field'||x.op==='merge_fields');
const structuralStages=(stages:ReviewStage[])=>stages.filter(stage=>
 stage.op!=='map_field'&&stage.op!=='cast_type');
/** Import never applies changes. Exact source hash and current reviewed format are required. */
export async function importReviewOnlyAIRecipe(
 text:string,source:string,draft:ParserDraft,suite:SuiteResult,
):Promise<AIImportResult>{
 if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>MAX_RECIPE_BYTES)
  return {ok:false,reason:'INPUT_TOO_LARGE'};
 if(!verified(source,suite))return {ok:false,reason:'UNTRUSTED_PREVIEW'};
 let value:unknown;
 try{value=JSON.parse(text) as unknown;}catch{return {ok:false,reason:'INVALID_JSON'};}
 if(!validateReviewableRecipe(value))return {ok:false,reason:'UNTRUSTED_RECIPE'};
 const current=await buildReviewableRecipe(source,draft,suite);
 if(!current.ok)return {ok:false,reason:'CURRENT_RECIPE_UNAVAILABLE'};
 const imported=value as ParserRecipeV2;
 if(imported.projectId!==current.recipe.projectId||
    imported.sample.sha256!==current.recipe.sample.sha256||
    imported.sample.events!==current.recipe.sample.events)
  return {ok:false,reason:'SOURCE_IDENTITY_MISMATCH'};
 if(imported.sourceFormat!==current.recipe.sourceFormat||
   imported.bodyFormat!==current.recipe.bodyFormat)
  return {ok:false,reason:'FORMAT_MISMATCH'};
 // Current v0.1 compiler cannot handle additional stages other than strictly
 // staged v0.2 review proposals. No execution, conversion or auto-approval here.
 const prior=current.recipe.stages,proposed=imported.stages;
 const priorMaps=mapping(prior),newMaps=mapping(proposed);
 const known=new Set(priorMaps.map(x=>x.target));
 const newTargets=new Set(newMaps.map(x=>x.target));
 const added=newMaps.filter(x=>!known.has(x.target)).length;
 const removed=priorMaps.filter(x=>!newTargets.has(x.target)).length;
 const length=Math.max(prior.length,proposed.length);
 let changed=0;
 for(let i=0;i<length;i++)if(JSON.stringify(prior[i])!==JSON.stringify(proposed[i]))changed++;
 return {ok:true,candidate:imported,baseline:current.recipe,report:{
   contract:'auto-parser.ai-import-review.v0.1',status:'REVIEW_ONLY',mode:'BASELINE_EDIT',
   changedStageCount:changed,addedMappings:added,removedMappings:removed,
   sampleEvents:imported.sample.events,backendCompilerAvailable:false,
   userApprovalRequired:true,rawLogsIncluded:false,
 }};
}

/** Import a full declarative recovery recipe when no compiler-ready baseline exists.
 * Exact source identity, project identity and strict v0.2 stage validation are required.
 */
export async function importRecoveryAIRecipe(
 text:string,source:string,draft:ParserDraft,suite:SuiteResult,
):Promise<AIImportResult>{
 if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>MAX_RECIPE_BYTES)
  return {ok:false,reason:'INPUT_TOO_LARGE'};
 if(!verified(source,suite))return {ok:false,reason:'UNTRUSTED_PREVIEW'};
 let value:unknown;
 try{value=JSON.parse(text) as unknown;}catch{return {ok:false,reason:'INVALID_JSON'};}
 if(!validateReviewableRecipe(value))return {ok:false,reason:'UNTRUSTED_RECIPE'};
 const imported=value as ParserRecipeV2;
 const opts=draft.guided??defaultGuidedOptions();
 const expectedProject='draft-'+opts.slug;
 const boundary=imported.stages[0]?.op==='split_event'?imported.stages[0].boundary:'single-line';
 const records=splitEvents(source,boundary,MAX_EVENTS+1);
 if(!records.length||records.length>MAX_EVENTS)return {ok:false,reason:'SOURCE_LIMIT'};
 let sourceHash:string;
 try{sourceHash=await digest(source);}catch{return {ok:false,reason:'UNTRUSTED_PREVIEW'};}
 if(imported.projectId!==expectedProject||imported.sample.sha256!==sourceHash||
    imported.sample.events!==records.length)
  return {ok:false,reason:'SOURCE_IDENTITY_MISMATCH'};
 const maps=mapping(imported.stages);
 return {ok:true,candidate:imported,baseline:null,report:{
   contract:'auto-parser.ai-import-review.v0.1',status:'REVIEW_ONLY',mode:'FULL_RECOVERY',
   changedStageCount:imported.stages.length,addedMappings:maps.length,removedMappings:draft.mappings.length,
   sampleEvents:records.length,backendCompilerAvailable:false,
   userApprovalRequired:true,rawLogsIncluded:false,
 }};
}

export type AIRecoveryProposal=
 | {ok:true;candidate:ParserDraft;approvalRequired:true;backendCompilerVerified:false;replacement:'FULL_PARSER'}
 | {ok:false;reason:'UNSUPPORTED_RECIPE'|'BACKEND_UNSUPPORTED'|'CLASSIFICATION_UNSUPPORTED'};
const INDEX_TO_UI={session:'Session',threat:'Threat',syslog:'Syslog',winlogevent:'Winlogevent'} as const;
/** Translate only the reviewed v0.2 operations that the current v0.1 backend can compile. */
export function proposeV01RecoveryParserFromAI(imported:AIImportResult,draft:ParserDraft):AIRecoveryProposal{
 const deny=(reason:Extract<AIRecoveryProposal,{ok:false}>['reason']):AIRecoveryProposal=>({ok:false,reason});
 if(!imported.ok||imported.report.mode!=='FULL_RECOVERY')return deny('UNSUPPORTED_RECIPE');
 const recipe=imported.candidate,opts=draft.guided??defaultGuidedOptions();
 if(recipe.projectId!=='draft-'+opts.slug)return deny('UNSUPPORTED_RECIPE');
 const maps=mapping(recipe.stages);
 if(!maps.length)return deny('UNSUPPORTED_RECIPE');
 const groups:Record<string,'top_fields'|'ns_fields'|'vendor_fields'>={};
 const mappings=maps.map((item,index)=>{
   const id='ai-recovery-'+String(index+1);groups[id]=item.group;
   return {id,source:item.source,target:item.target,
     type:(item.data_type==='date'?'timestamp':item.data_type) as ParserDraft['mappings'][number]['type']};
 });
 const classify=recipe.stages.find((s):s is Extract<ReviewStage,{op:'classify'}>=>s.op==='classify');
 if(!classify)return deny('UNSUPPORTED_RECIPE');
 const rules=[] as NonNullable<ParserDraft['guided']>['classification']['rules'];
 for(const [index,rule] of classify.rules.entries()){
   const mapped=maps.find(item=>item.target===rule.field&&item.group!=='vendor_fields');
   if(!mapped)return deny('CLASSIFICATION_UNSUPPORTED');
   rules.push({id:'ai-class-'+String(index+1),sourceField:mapped.source,equals:rule.value,
     index:INDEX_TO_UI[rule.index]});
 }
 const split=recipe.stages[0];
 if(split?.op!=='split_event')return deny('UNSUPPORTED_RECIPE');
 const recipeEnrichment=enrichment(recipe.stages).map((stage,index)=>stage.op==='split_field'?{
   id:'ai-enrich-'+String(index+1),operator:'split_field' as const,source:stage.source,target:'',value:'',
   delimiter:stage.delimiter,targets:[...stage.targets]}:{
   id:'ai-enrich-'+String(index+1),operator:'merge_fields' as const,source:'',target:stage.target,value:'',
   delimiter:stage.delimiter,sources:[...stage.sources]});
 const nextOpts={...opts,enrichment:recipeEnrichment,eventBoundary:split.boundary,groups,
   receiver:{...opts.receiver,
     protocols:split.boundary==='blank-line'?['tcp' as const]:opts.receiver.protocols,
     framing:split.boundary==='blank-line'?(recipe.sourceFormat==='java_stacktrace'?'blank_line_java' as const:'blank_line_json' as const):'newline' as const},
   classification:{defaultIndex:INDEX_TO_UI[classify.defaultIndex],rules}};
 const parseCsv=recipe.stages.find((s):s is Extract<ReviewStage,{op:'parse_csv'}>=>s.op==='parse_csv');
 const parseRegex=recipe.stages.find((s):s is Extract<ReviewStage,{op:'parse_regex'}>=>s.op==='parse_regex');
 const dispatch=recipe.stages.find((s):s is Extract<ReviewStage,{op:'dispatch_family'}>=>s.op==='dispatch_family');
 const candidate:ParserDraft={...draft,format:recipe.sourceFormat,mappings,guided:nextOpts,
   ...(recipe.sourceFormat==='csv'&&parseCsv?{csvColumns:parseCsv.columns.join(','),csvDelimiter:parseCsv.delimiter}:{}),
   ...(recipe.sourceFormat==='regex'&&parseRegex?{pattern:parseRegex.pattern}:{}),
   ...(recipe.sourceFormat==='mixed'&&dispatch?{mixedFormats:[...dispatch.families]}:{}),
   ...(['syslog_rfc3164','syslog_rfc5424'].includes(recipe.sourceFormat)?
     {syslogBodyFormat:recipe.bodyFormat as 'json'|'kv'|'cef'|'leef'|'regex',...(recipe.bodyFormat==='regex'&&parseRegex?{pattern:parseRegex.pattern}:{})}:{})};
 if(!toBackendProject(candidate).ok)return deny('BACKEND_UNSUPPORTED');
 return {ok:true,candidate,approvalRequired:true,backendCompilerVerified:false,replacement:'FULL_PARSER'};
}

/** Conservatively translate only ONE additive AI map_field to current v0.1.
 * Unchanged parser family, stages, old mappings and classification are mandatory.
 * The result is a proposed draft, never an applied or native-verified parser.
 */
export type AIFieldProposal=
 | {ok:true;candidate:ParserDraft;source:string;target:string;
     approvalRequired:true;backendCompilerVerified:false}
 | {ok:false;reason:'UNSUPPORTED_OPERATOR_CHANGE'|'NO_SINGLE_SAFE_MAPPING'|
     'SOURCE_NOT_PRESENT'|'BACKEND_UNSUPPORTED'};
export function proposeV01FieldMappingFromAI(
 imported:AIImportResult,source:string,draft:ParserDraft,suite:SuiteResult,
):AIFieldProposal{
 const deny=(reason:Extract<AIFieldProposal,{ok:false}>['reason']):AIFieldProposal=>({ok:false,reason});
 if(!imported.ok||imported.report.mode!=='BASELINE_EDIT'||!imported.baseline||!verified(source,suite))
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const proposed=imported.candidate;
 if(JSON.stringify(structuralStages(proposed.stages))!==JSON.stringify(structuralStages(imported.baseline.stages)))
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const old=toBackendProject(draft);
 if(!old.ok||old.project.projectId!==proposed.projectId)return deny('BACKEND_UNSUPPORTED');
 const oldMappings=draft.mappings;
 const proposedMappings=mapping(proposed.stages);
 if(proposedMappings.length!==oldMappings.length+1)
  return deny('NO_SINGLE_SAFE_MAPPING');
 const opts=draft.guided??defaultGuidedOptions();
 const consistent=new Set<string>();
 for(const rule of oldMappings){
  const group=opts.groups[rule.id]??'vendor_fields';
  const expectedType=rule.type==='timestamp'?'date':rule.type;
  const found=proposedMappings.find(m=>m.source===rule.source&&m.target===rule.target&&
   m.group===group&&m.data_type===expectedType);
  if(!found)return deny('UNSUPPORTED_OPERATOR_CHANGE');
  consistent.add(found.target);
 }
 const extra=proposedMappings.filter(m=>!consistent.has(m.target));
 if(extra.length!==1)return deny('NO_SINGLE_SAFE_MAPPING');
 const candidateMap=extra[0]!;
 const type=candidateMap.data_type==='date'?'timestamp':candidateMap.data_type;
 if(oldMappings.some(m=>m.source===candidateMap.source||
    m.target===candidateMap.target||m.target.startsWith(candidateMap.target+'.')||
    candidateMap.target.startsWith(m.target+'.')))
  return deny('NO_SINGLE_SAFE_MAPPING');
 if(!suite.events.every(event=>{
   if(!event.extracted)return false;
   const item=lookupFieldValue(event.fields,candidateMap.source);
   return item.found&&item.value!==undefined&&item.value!==null&&
    typeof item.value!=='object';
 }))return deny('SOURCE_NOT_PRESENT');
 // The runtime schema validator has already checked stage order and casts.
 const stagedClass=proposed.stages.find(s=>s.op==='classify');
 if(stagedClass?.op!=='classify'||
   JSON.stringify(stagedClass.rules)!==JSON.stringify(old.project.classification.rules)||
   stagedClass.defaultIndex!==old.project.classification.defaultIndex)
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const id='ai-reviewed-'+String(oldMappings.length+1);
 if(oldMappings.some(m=>m.id===id))return deny('NO_SINGLE_SAFE_MAPPING');
 const result:ParserDraft={...draft,
  mappings:[...draft.mappings,{id,source:candidateMap.source,target:candidateMap.target,
    type:type as typeof oldMappings[number]['type']}],
  guided:{...opts,groups:{...opts.groups,[id]:candidateMap.group}}};
 if(!toBackendProject(result).ok)return deny('BACKEND_UNSUPPORTED');
 return {ok:true,candidate:result,source:candidateMap.source,
  target:candidateMap.target,approvalRequired:true,backendCompilerVerified:false};
}

export type AIEnrichmentProposal=
 | {ok:true;candidate:ParserDraft;operator:'split_field'|'merge_fields';approvalRequired:true;
     backendCompilerVerified:false;replacement:'ONE_ENRICHMENT'}
 | {ok:false;reason:'UNSUPPORTED_OPERATOR_CHANGE'|'NO_SINGLE_ENRICHMENT_CHANGE'|'BACKEND_UNSUPPORTED'};
/** Add exactly one bounded declarative split/merge step while preserving every existing parser rule. */
export function proposeV01EnrichmentFromAI(
 imported:AIImportResult,source:string,draft:ParserDraft,suite:SuiteResult,
):AIEnrichmentProposal{
 const deny=(reason:Extract<AIEnrichmentProposal,{ok:false}>['reason']):AIEnrichmentProposal=>({ok:false,reason});
 if(!imported.ok||imported.report.mode!=='BASELINE_EDIT'||!imported.baseline||!verified(source,suite))
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const strip=(stages:ReviewStage[])=>stages.filter(stage=>stage.op!=='split_field'&&stage.op!=='merge_fields');
 if(JSON.stringify(strip(imported.candidate.stages))!==JSON.stringify(strip(imported.baseline.stages)))
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const before=enrichment(imported.baseline.stages),after=enrichment(imported.candidate.stages);
 if(after.length!==before.length+1||JSON.stringify(after.slice(0,-1))!==JSON.stringify(before))
  return deny('NO_SINGLE_ENRICHMENT_CHANGE');
 const stage=after.at(-1)!;
 const opts=draft.guided??defaultGuidedOptions();
 const existing=opts.enrichment??[];
 if(existing.length!==before.length)return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const id='ai-enrichment-'+String(existing.length+1);
 const rule=stage.op==='split_field'?{
   id,operator:'split_field' as const,source:stage.source,target:'',value:'',
   delimiter:stage.delimiter,targets:[...stage.targets]
 }:{
   id,operator:'merge_fields' as const,source:'',target:stage.target,value:'',
   delimiter:stage.delimiter,sources:[...stage.sources]
 };
 const candidate:ParserDraft={...draft,guided:{...opts,enrichment:[...existing,rule]}};
 if(!toBackendProject(candidate).ok)return deny('BACKEND_UNSUPPORTED');
 return {ok:true,candidate,operator:stage.op,approvalRequired:true,
   backendCompilerVerified:false,replacement:'ONE_ENRICHMENT'};
}

export type AIMappingCorrectionProposal=
 | {ok:true;candidate:ParserDraft;mappingId:string;oldTarget:string;newTarget:string;
     approvalRequired:true;backendCompilerVerified:false;replacement:'ONE_MAPPING'}
 | {ok:false;reason:'UNSUPPORTED_OPERATOR_CHANGE'|'NO_SINGLE_MAPPING_CHANGE'|'SOURCE_NOT_PRESENT'|'BACKEND_UNSUPPORTED'};
/** Replace exactly one existing mapping while preserving parser grammar and all unrelated mappings. */
export function proposeV01MappingCorrectionFromAI(
 imported:AIImportResult,source:string,draft:ParserDraft,suite:SuiteResult,
):AIMappingCorrectionProposal{
 const deny=(reason:Extract<AIMappingCorrectionProposal,{ok:false}>['reason']):AIMappingCorrectionProposal=>({ok:false,reason});
 if(!imported.ok||imported.report.mode!=='BASELINE_EDIT'||!imported.baseline||!verified(source,suite))
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const shell=(stages:ReviewStage[])=>stages.filter(stage=>
  stage.op!=='map_field'&&stage.op!=='cast_type'&&stage.op!=='classify');
 if(JSON.stringify(shell(imported.candidate.stages))!==JSON.stringify(shell(imported.baseline.stages)))
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const oldProject=toBackendProject(draft);
 if(!oldProject.ok||oldProject.project.projectId!==imported.candidate.projectId)
  return deny('BACKEND_UNSUPPORTED');
 const before=mapping(imported.baseline.stages),after=mapping(imported.candidate.stages);
 if(before.length!==draft.mappings.length||after.length!==before.length)return deny('NO_SINGLE_MAPPING_CHANGE');
 const changed=after.map((item,index)=>JSON.stringify(item)!==JSON.stringify(before[index])?index:-1)
  .filter(index=>index>=0);
 if(changed.length!==1)return deny('NO_SINGLE_MAPPING_CHANGE');
 const index=changed[0]!,next=after[index]!,prior=draft.mappings[index];
 if(!prior)return deny('NO_SINGLE_MAPPING_CHANGE');
 if(!suite.events.every(event=>{
  if(!event.extracted)return false;
  const item=lookupFieldValue(event.fields,next.source);
  return item.found&&item.value!==undefined&&item.value!==null&&typeof item.value!=='object';
 }))return deny('SOURCE_NOT_PRESENT');
 const opts=draft.guided??defaultGuidedOptions();
 const candidate:ParserDraft={...draft,mappings:draft.mappings.map((rule,i)=>i===index?{
   ...rule,source:next.source,target:next.target,
   type:(next.data_type==='date'?'timestamp':next.data_type) as typeof rule.type}:rule),
  guided:{...opts,groups:{...opts.groups,[prior.id]:next.group}}};
 const adapted=toBackendProject(candidate);
 if(!adapted.ok)return deny('BACKEND_UNSUPPORTED');
 const stagedClass=imported.candidate.stages.find((stage):stage is Extract<ReviewStage,{op:'classify'}>=>stage.op==='classify');
 if(!stagedClass||JSON.stringify(stagedClass.rules)!==JSON.stringify(adapted.project.classification.rules)||
    stagedClass.defaultIndex!==adapted.project.classification.defaultIndex)
  return deny('UNSUPPORTED_OPERATOR_CHANGE');
 return {ok:true,candidate,mappingId:prior.id,oldTarget:prior.target,newTarget:next.target,
   approvalRequired:true,backendCompilerVerified:false,replacement:'ONE_MAPPING'};
}
