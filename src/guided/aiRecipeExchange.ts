/** P1-AP6 offline, user-directed AI prompt and strict REVIEW_ONLY import.
 * No provider calls, raw sample export, Ruby, Regex or JSONata execution.
 */
import type {ParserDraft,SuiteResult} from '../model';
import {MAX_DATASET_BYTES,MAX_EVENTS,splitEvents} from '../parser';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {buildReviewableRecipe,validateReviewableRecipe,
 type ParserRecipeV2,type ReviewStage} from './parserRecipeV2';
import {toBackendProject} from './backendAdapter';
import {lookupFieldValue} from '../fieldPaths';
import {defaultGuidedOptions} from './contract';

const MAX_RECIPE_BYTES=32*1024;
export type AIExchangeReason='SOURCE_LIMIT'|'UNTRUSTED_PREVIEW'|
 'PROJECT_UNSUPPORTED'|'CURRENT_RECIPE_UNAVAILABLE'|'INPUT_TOO_LARGE'|
 'INVALID_JSON'|'UNTRUSTED_RECIPE'|'SOURCE_IDENTITY_MISMATCH'|
 'FORMAT_MISMATCH'|'UNSUPPORTED_OPERATION';
export type AIPromptResult=
 | {ok:true;prompt:string;sampleSha256:string;sourceCount:number;
     rawLogsIncluded:false;automaticUpload:false}
 | {ok:false;reason:AIExchangeReason};
export type AIImportResult=
 | {ok:true;candidate:ParserRecipeV2;
     report:{contract:'auto-parser.ai-import-review.v0.1';
       status:'REVIEW_ONLY';changedStageCount:number;addedMappings:number;
       removedMappings:number;sampleEvents:number;backendCompilerAvailable:false;
       userApprovalRequired:true;rawLogsIncluded:false}}
 | {ok:false;reason:AIExchangeReason};

async function digest(text:string):Promise<string>{
 if(!globalThis.crypto?.subtle)throw new Error('SECURE_DIGEST_REQUIRED');
 const raw=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));
 return [...new Uint8Array(raw)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
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
 if(!projected.ok)return {ok:false,reason:'PROJECT_UNSUPPORTED'};
 const ledger=analyzeLogEnvelopes(source,'single-line');
 if(ledger.status!=='READY'||ledger.accounted!==suite.events.length)
  return {ok:false,reason:'SOURCE_LIMIT'};
 const hash=await digest(source);
 const families=ledger.families.map(({envelope,body,count})=>({envelope,body,count}));
 const meta={projectId:projected.project.projectId,sourceCount:ledger.sourceCount,
  sourceHash:hash,families,unsupported:ledger.unsupported};
 const prompt=[
  'Create a conservative Parser Studio v0.2 REVIEW_ONLY JSON recipe proposal.',
  'The JSON object MUST contain only these root keys:',
  'contract, schemaRevision, compilerMode, projectId, sourceFormat, bodyFormat, sample, stages, nativeVerified, targetVerified.',
  'Use contract parser-studio.recipe.v0.2; schemaRevision 0.2; compilerMode REVIEW_ONLY; nativeVerified=false; targetVerified=false.',
  'projectId must match the metadata below; sample must be {sha256: sourceHash, events: sourceCount}.',
  'Allow only stages: split_event(single-line), optional unwrap_syslog(version 1, strict_header),',
  'one parse_json/parse_kv/parse_cef/parse_leef/parse_csv, map_field, adjacent cast_type, classify, fallback_unparsed.',
  'Never provide Ruby, executable code, Regex, JSONata, credentials, API requests or deployment instructions.',
  'Refuse to assert a supported grammar when family metadata is insufficient or mixed.',
  'All rules require local user review. Native Fluentd and Stellar target import are NOT VERIFIED.',
  'Only count, family and digest metadata follow. No raw logs or field values have been included:',
  JSON.stringify(meta),
  'If you need more context, ASK for explicitly user-approved, manually redacted example records; do not invent semantics.',
 ].join('\n');
 return {ok:true,prompt,sampleSha256:hash,sourceCount:ledger.sourceCount,
  rawLogsIncluded:false,automaticUpload:false};
}
const mapping=(stages:ReviewStage[])=>stages.filter(
 (x):x is Extract<ReviewStage,{op:'map_field'}>=>x.op==='map_field');
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
 return {ok:true,candidate:imported,report:{
   contract:'auto-parser.ai-import-review.v0.1',status:'REVIEW_ONLY',
   changedStageCount:changed,addedMappings:added,removedMappings:removed,
   sampleEvents:imported.sample.events,backendCompilerAvailable:false,
   userApprovalRequired:true,rawLogsIncluded:false,
 }};
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
 if(!imported.ok||!verified(source,suite))return deny('UNSUPPORTED_OPERATOR_CHANGE');
 const proposed=imported.candidate;
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
