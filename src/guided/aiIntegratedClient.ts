/** AP6 optional external model via a separately authorized private backend.
 * Always metadata-only. No raw sample, field values, arbitrary user prompt,
 * customer/provider API key, DP credentials, dynamic URL or auto-apply.
 */
import type {ParserDraft,SuiteResult} from '../model';
import {createPrivacySafeAIPrompt} from './aiRecipeExchange';
import {analyzeLogEnvelopes,type Envelope,type Body} from './autoParserEnvelope';
import {toBackendProject} from './backendAdapter';
import {validateReviewableRecipe,type ParserRecipeV2} from './parserRecipeV2';

const BASE='/api/v1/parser-pairs/ai/v0.1';
const SAFE_ID=/^[A-Za-z0-9_.:@-]{1,128}$/;
const SHA=/^[0-9a-f]{64}$/;
export interface AIReviewMetadata{
 contract:'parser-studio.ai-metadata.v0.1';
 projectId:string;sampleSha256:string;sampleEvents:number;
 sourceFormat:'json'|'kv'|'csv'|'cef'|'leef'|'syslog_rfc3164'|'syslog_rfc5424'|'mixed';
 bodyFormat:'json'|'kv'|'csv'|'cef'|'leef'|'mixed';
 unsupported:0;
 families:Array<{envelope:Envelope;body:Body;count:number}>;
}
export interface AIProviderCapability {
 contract:'parser-studio.ai-capabilities.v0.1';
 available:true;providerId:string;modelId:string;
 externalTransfer:'METADATA_ONLY';
 noRawLogs:true;requiresExplicitConfirmation:true;
 requiresBudgetConfirmation:true;auditBeforeProvider:true;
 requiresServerBudgetReservation:true;
 maxOutputTokens:number;userApprovalRequired:true;
 nativeParserVerified:false;targetImportVerified:false;
}
export type AIProviderAvailability={status:'DISABLED'}|
 {status:'AVAILABLE';capability:AIProviderCapability};
export interface AIReviewedCandidate{
 contract:'parser-studio.ai-reviewed-candidate.v0.1';
 recipe:ParserRecipeV2;externalTransfer:'METADATA_ONLY';
 usage:{outputTokens:number;reservedOutputTokens:number};
 userApprovalRequired:true;nativeParserVerified:false;
 targetImportVerified:false;rawLogsIncluded:false;
 providerId:string;modelId:string;
}
function strict(raw:unknown,keys:readonly string[]):raw is Record<string,unknown>{
 return raw!==null&&typeof raw==='object'&&!Array.isArray(raw)&&
  Object.keys(raw).length===keys.length&&
  Object.keys(raw).every(key=>keys.includes(key));
}
function deny():never{throw new Error('The optional AI provider metadata or review could not be verified.');}
export async function probeAIReviewAvailability(requester:typeof fetch=fetch):Promise<AIProviderAvailability>{
 const resp=await requester(BASE+'/capabilities',{
  method:'GET',cache:'no-store',credentials:'same-origin',
  headers:{Accept:'application/json'},
 });
 if(resp.status===403||resp.status===404)return {status:'DISABLED'};
 if(resp.status!==200)deny();
 let raw:unknown;
 try{raw=await resp.json();}catch{deny();}
 if(!strict(raw,[
  'contract','available','providerId','modelId','externalTransfer',
  'noRawLogs','requiresExplicitConfirmation','requiresBudgetConfirmation',
  'auditBeforeProvider','requiresServerBudgetReservation','maxOutputTokens',
  'userApprovalRequired','nativeParserVerified','targetImportVerified',
 ])||
  raw.contract!=='parser-studio.ai-capabilities.v0.1'||
  raw.available!==true||typeof raw.providerId!=='string'||
  !SAFE_ID.test(raw.providerId)||typeof raw.modelId!=='string'||
  !SAFE_ID.test(raw.modelId)||raw.externalTransfer!=='METADATA_ONLY'||
  raw.noRawLogs!==true||raw.requiresExplicitConfirmation!==true||
  raw.requiresBudgetConfirmation!==true||raw.auditBeforeProvider!==true||
  raw.requiresServerBudgetReservation!==true||
  !Number.isSafeInteger(raw.maxOutputTokens)||
  Number(raw.maxOutputTokens)<32||Number(raw.maxOutputTokens)>1024||
  raw.userApprovalRequired!==true||raw.nativeParserVerified!==false||
  raw.targetImportVerified!==false)deny();
 return {status:'AVAILABLE',capability:raw as unknown as AIProviderCapability};
}
/** Recompute an exact census and fresh local SHA. Never infer a parser project. */
export async function deriveAIMetadata(
 raw:string,draft:ParserDraft,suite:SuiteResult,
):Promise<AIReviewMetadata>{
 const prompt=await createPrivacySafeAIPrompt(raw,draft,suite);
 if(!prompt.ok||!prompt.currentProjectImportReady||!SHA.test(prompt.sampleSha256))deny();
 const converted=toBackendProject(draft);
 if(!converted.ok)deny();
 const census=analyzeLogEnvelopes(raw,'single-line');
 if(census.status!=='READY'||!census.complete||census.unsupported!==0||
  census.sourceCount!==prompt.sourceCount||
  census.accounted!==prompt.sourceCount||
  census.families.length<1||census.families.length>4)deny();
 const sourceFormat=converted.project.extraction.format;
 // The optional metadata-only LLM contract does not include Java Stack Trace:
 // no provider egress even if source timestamps and framing are recognized.
 if(sourceFormat==='java_stacktrace')deny();
 const bodyFormat=sourceFormat==='mixed'?'mixed':
  sourceFormat==='syslog_rfc3164'||sourceFormat==='syslog_rfc5424'?
   converted.project.extraction.syslogBodyFormat:sourceFormat;
 // The integrated metadata-only AI gateway intentionally does not guess
 // mixed Syslog semantics. Keep wrapped Syslog in deterministic compiler
 // review until the provider schema explicitly defines that safer transfer.
 if(sourceFormat==='mixed'&&census.families.some(x=>x.envelope!=='none'))deny();
 if(bodyFormat===undefined||bodyFormat==='raw')deny();
 // Census is strictly stable enum identifiers and counts, never event text.
 const allowed=['json','kv','csv','cef','leef','mixed'];
 if(!allowed.includes(bodyFormat))deny();
 return {
  contract:'parser-studio.ai-metadata.v0.1',
  projectId:converted.project.projectId,sampleSha256:prompt.sampleSha256,
  sampleEvents:prompt.sourceCount,sourceFormat,
  bodyFormat:bodyFormat as AIReviewMetadata['bodyFormat'],
  unsupported:0,
  families:census.families.map(item=>({
   envelope:item.envelope,body:item.body,count:item.count,
  })),
 };
}
function verifiedCandidate(raw:unknown,cap:AIProviderCapability,meta:AIReviewMetadata):AIReviewedCandidate{
 if(!strict(raw,['contract','recipe','externalTransfer','usage',
  'userApprovalRequired','nativeParserVerified','targetImportVerified',
  'rawLogsIncluded','providerId','modelId'])||
  raw.contract!=='parser-studio.ai-reviewed-candidate.v0.1'||
  raw.externalTransfer!=='METADATA_ONLY'||
  raw.userApprovalRequired!==true||
  raw.nativeParserVerified!==false||raw.targetImportVerified!==false||
  raw.rawLogsIncluded!==false||raw.providerId!==cap.providerId||
  raw.modelId!==cap.modelId||
  !strict(raw.usage,['outputTokens','reservedOutputTokens'])||
  !Number.isSafeInteger(raw.usage.outputTokens)||
  Number(raw.usage.outputTokens)<1||
  Number(raw.usage.outputTokens)>cap.maxOutputTokens||
  raw.usage.reservedOutputTokens!==cap.maxOutputTokens||
  !validateReviewableRecipe(raw.recipe))deny();
 const recipe=raw.recipe as ParserRecipeV2;
 if(recipe.sample.sha256!==meta.sampleSha256||
  recipe.sample.events!==meta.sampleEvents||
  recipe.projectId!==meta.projectId||
  recipe.sourceFormat!==meta.sourceFormat||
  recipe.bodyFormat!==meta.bodyFormat||
  recipe.nativeVerified!==false||recipe.targetVerified!==false||
  recipe.compilerMode!=='REVIEW_ONLY')deny();
 return raw as unknown as AIReviewedCandidate;
}
/** No POST until both distinct user approvals are true and capability was verified. */
export async function requestAIReviewedCandidate(
 raw:string,draft:ParserDraft,suite:SuiteResult,
 cap:AIProviderCapability,approvedExternal:boolean,approvedTokens:boolean,
 requester:typeof fetch=fetch,
):Promise<AIReviewedCandidate>{
 if(!approvedExternal||!approvedTokens)
  throw new Error('Separate external metadata and token budget approvals required.');
 if(!cap||cap.contract!=='parser-studio.ai-capabilities.v0.1'||
  cap.noRawLogs!==true||cap.externalTransfer!=='METADATA_ONLY'||
  cap.userApprovalRequired!==true||cap.nativeParserVerified!==false||
  cap.targetImportVerified!==false)deny();
 const metadata=await deriveAIMetadata(raw,draft,suite);
 const body=JSON.stringify({
  contract:'parser-studio.ai-request.v0.1',metadata,
  confirmedExternalTransfer:true,confirmedEstimatedTokenBudget:true,
 });
 if(new TextEncoder().encode(body).byteLength>3072)deny();
 const response=await requester(BASE+'/review',{
  method:'POST',cache:'no-store',credentials:'same-origin',
  headers:{Accept:'application/json','Content-Type':'application/json'},
  body,
 });
 if(response.status!==200)throw new Error('The private AI model was not available or could not complete the reviewed request.');
 let reply:unknown;
 try{reply=await response.json();}catch{deny();}
 return verifiedCandidate(reply,cap,metadata);
}
