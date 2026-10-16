/**
 * Explicit source-bound Native Fluentd verification.
 *
 * Availability is rechecked immediately before any POST. Raw source is sent
 * only after a user-triggered call and only to a same-origin backend that
 * explicitly advertises the authenticated per-project verifier.
 */
import type {SuiteResult} from '../model';
import {sha256Utf8Hex} from '../sha256';
import type {BackendField,BackendParserProject} from './backendAdapter';
import type {ReviewedRecipeCompilation} from './recipeV2BackendClient';
import type {ParserRecipeV2} from './parserRecipeV2';

const BASE='/api/v1/parser-pairs/recipe/v0.2';
const SHA=/^[a-f0-9]{64}$/;
const SAFE=/^[A-Za-z_][A-Za-z0-9_-]*$/;
const UNSAFE=new Set(['__proto__','constructor','prototype']);

export class NativeProjectVerificationUnavailable extends Error{
 constructor(message='Native Fluentd verification is unavailable.'){
  super(message);this.name='NativeProjectVerificationUnavailable';
 }
}
export interface NativeProjectVerificationReport{
 contract:'parser-studio.native-project-verification.v0.1';
 sourceSha256:string;recipeSha256:string;parserSha256:string;confSha256:string;
 eventCount:number;eventsPassed:number;recordHashMatches:number;eventTimeMatches:number;
 ruby:'3.2';fluentd:'1.17.1';confAstVerified:true;parserCallbackVerified:true;
 sourceHashVerifiedAgainstEvents:true;nativeUserParserVerified:true;
 targetImportVerified:false;sensorTrafficSent:false;rawValuesReturned:false;
}

function untrusted():never{throw new Error('Native project verification response is untrusted.');}
function blank():Record<string,unknown>{return Object.create(null) as Record<string,unknown>;}
function canonicalJson(value:unknown):string{
 if(Array.isArray(value))return '['+value.map(canonicalJson).join(',')+']';
 if(value!==null&&typeof value==='object'){
  const record=value as Record<string,unknown>;
  return '{'+Object.keys(record).sort().map(key=>
   JSON.stringify(key)+':'+canonicalJson(record[key])).join(',')+'}';
 }
 const encoded=JSON.stringify(value);if(encoded===undefined)untrusted();return encoded;
}
function safePath(path:string):string[]{
 const parts=path.split('.');
 if(!parts.length||parts.some(x=>!SAFE.test(x)||UNSAFE.has(x)))untrusted();
 return parts;
}
function assign(record:Record<string,unknown>,path:string,value:unknown):void{
 const parts=safePath(path);let cursor=record;
 for(const part of parts.slice(0,-1)){
  const prior=cursor[part];
  if(prior===undefined){const next=blank();cursor[part]=next;cursor=next;continue;}
  if(!prior||typeof prior!=='object'||Array.isArray(prior))untrusted();
  cursor=prior as Record<string,unknown>;
 }
 const leaf=parts.at(-1)!;
 if(Object.prototype.hasOwnProperty.call(cursor,leaf))untrusted();
 cursor[leaf]=value;
}
function lookup(record:Record<string,unknown>,path:string):unknown{
 let value:unknown=record;
 for(const part of safePath(path)){
  if(!value||typeof value!=='object'||Array.isArray(value)||
     !Object.prototype.hasOwnProperty.call(value,part))return undefined;
  value=(value as Record<string,unknown>)[part];
 }
 return value;
}
function backendValue(value:unknown,rule:BackendField):unknown{
 switch(rule.data_type){
  case 'string':
   if(typeof value!=='string')untrusted();return value;
  case 'integer':
  case 'port':
   if(typeof value!=='number'||!Number.isSafeInteger(value)||
      (rule.data_type==='port'&&(value<0||value>65535)))untrusted();
   return value;
  case 'boolean':
   if(typeof value!=='boolean')untrusted();return value;
  case 'ip':
   if(typeof value!=='string')untrusted();
   // Ruby IPAddr canonicalizes IPv6. Until the browser-side canonicalizer is
   // independently proven byte-equivalent, do not create a misleading hash.
   if(value.includes(':'))throw new Error(
     'Native expected output currently requires canonical IPv4 values.');
   return value;
  case 'date':{
   if(typeof value!=='string'||!/(?:Z|[+-]\d{2}:\d{2})$/.test(value))untrusted();
   const milliseconds=Date.parse(value);
   if(!Number.isSafeInteger(milliseconds))untrusted();
   return milliseconds;
  }
 }
}
function browserValue(normalized:Record<string,unknown>,target:string,rule:BackendField):unknown{
 const value=lookup(normalized,target);
 if(value===undefined)untrusted();
 return backendValue(value,rule);
}
function expectedRecord(normalized:Record<string,unknown>,project:BackendParserProject):
 {record:Record<string,unknown>;eventTimeMs:number|null}{
 const record=blank();
 for(const section of [project.normalization.topFields,project.normalization.nsFields])
  for(const rule of Object.values(section))
   assign(record,rule.normalized_name,browserValue(normalized,rule.normalized_name,rule));

 const vendorRules=Object.values(project.normalization.vendorFields);
 if(vendorRules.length){
  if(UNSAFE.has(project.vendor))untrusted();
  const browserVendor=normalized[project.vendor];
  if(!browserVendor||typeof browserVendor!=='object'||Array.isArray(browserVendor))untrusted();
  const vendor=blank();
  for(const rule of vendorRules){
   const value=lookup(browserVendor as Record<string,unknown>,rule.normalized_name);
   if(value===undefined)untrusted();
   assign(vendor,rule.normalized_name,backendValue(value,rule));
  }
  if(Object.prototype.hasOwnProperty.call(record,project.vendor))untrusted();
  record[project.vendor]=vendor;
 }

 for(const rule of project.enrichment??[]){
  const targets=rule.operator==='split_field'?rule.targets:[rule.target];
  for(const target of targets){
   const value=lookup(normalized,target);
   if(value===undefined)untrusted();
   assign(record,target,value);
  }
 }

 let index=project.classification.defaultIndex;
 for(const rule of project.classification.rules){
  if(lookup(record,rule.field)===rule.value){index=rule.index;break;}
 }
 assign(record,'stellar_log_index',index);
 assign(record,'msg_origin',{
  source:project.normalization.msgOriginSource,
  category:project.normalization.msgOriginCategory,
  class:project.normalization.msgClass,
 });
 const timestamp=lookup(record,'timestamp');
 return {record,eventTimeMs:
  typeof timestamp==='number'&&Number.isSafeInteger(timestamp)?timestamp:null};
}

export async function buildNativeExpectedEvents(
 suite:SuiteResult,recipe:ParserRecipeV2,project:BackendParserProject,
):Promise<Array<{eventId:string;recordSha256:string;eventTimeMs:number|null}>>{
 if(suite.engine!=='browser-preview'||suite.nativeFluentdVerified!==false||
   suite.stellarExportVerified!==false||suite.events.length<1||
   suite.events.length!==recipe.sample.events||
   suite.events.some((event,index)=>event.id!==`event-${index+1}`||
     !event.normalizedOk||event.status==='fail'))untrusted();
 return Promise.all(suite.events.map(async event=>{
  const expected=expectedRecord(event.normalized,project);
  return {eventId:event.id,recordSha256:await sha256Utf8Hex(canonicalJson(expected.record)),
   eventTimeMs:expected.eventTimeMs};
 }));
}

export async function checkNativeProjectVerificationAvailability(
 requester:typeof fetch=fetch,
):Promise<boolean>{
 const response=await requester(BASE+'/capabilities',{
  method:'GET',cache:'no-store',credentials:'same-origin',headers:{Accept:'application/json'},
 });
 if(response.status===404)return false;
 if(response.status!==200)untrusted();
 let raw:unknown;try{raw=await response.json();}catch{untrusted();}
 if(!raw||typeof raw!=='object'||Array.isArray(raw))untrusted();
 const cap=raw as Record<string,unknown>;
 if(cap.contract!=='parser-studio.recipe.v0.2'||
   cap.nativeUserParserVerified!==false||cap.targetImportVerified!==false||
   cap.sourceHashVerifiedAgainstEvents!==false||cap.apiDoesNotDeploy!==true)untrusted();
 if(cap.nativeProjectVerificationConfigured===undefined)return false;
 if(typeof cap.nativeProjectVerificationConfigured!=='boolean'||
   cap.nativeProjectVerificationRequiresAuth!==true)untrusted();
 return cap.nativeProjectVerificationConfigured;
}

export async function verifyNativeProject(
 input:{source:string;suite:SuiteResult;recipe:ParserRecipeV2;
   legacyProject:BackendParserProject;compiled:ReviewedRecipeCompilation},
 requester:typeof fetch=fetch,
):Promise<NativeProjectVerificationReport>{
 // Critical privacy gate: no raw source POST until this fresh data-free probe passes.
 if(!await checkNativeProjectVerificationAvailability(requester))
  throw new NativeProjectVerificationUnavailable();

 const expected=await buildNativeExpectedEvents(input.suite,input.recipe,input.legacyProject);
 if(expected.length>500||new TextEncoder().encode(input.source).byteLength>64*1024)
  untrusted();
 const body=JSON.stringify({
  contract:'parser-studio.native-project-request.v0.1',confirmed:true,
  recipe:input.recipe,legacyProject:input.legacyProject,source:input.source,expected,
 });
 if(new TextEncoder().encode(body).byteLength>448*1024)untrusted();
 const response=await requester(BASE+'/native-verify',{
  method:'POST',cache:'no-store',credentials:'same-origin',
  headers:{'Content-Type':'application/json',Accept:'application/json'},body,
 });
 if(response.status!==200)throw new NativeProjectVerificationUnavailable(
   'Native Fluentd verification was denied or unavailable ('+response.status+').');
 let raw:unknown;try{raw=await response.json();}catch{untrusted();}
 if(!raw||typeof raw!=='object'||Array.isArray(raw))untrusted();
 const report=raw as Partial<NativeProjectVerificationReport>;
 const conf=input.compiled.pair.files.filter(file=>file.name.endsWith('.conf'));
 const parser=input.compiled.pair.files.filter(file=>!file.name.endsWith('.conf'));
 if(conf.length!==1||parser.length!==1)untrusted();
 if(report.contract!=='parser-studio.native-project-verification.v0.1'||
   report.sourceSha256!==input.recipe.sample.sha256||
   report.recipeSha256!==input.compiled.receipt.recipeSha256||
   report.parserSha256!==parser[0]!.sha256||report.confSha256!==conf[0]!.sha256||
   !report.sourceSha256||!SHA.test(report.sourceSha256)||
   !report.recipeSha256||!SHA.test(report.recipeSha256)||
   !report.parserSha256||!SHA.test(report.parserSha256)||
   !report.confSha256||!SHA.test(report.confSha256)||
   report.eventCount!==expected.length||report.eventsPassed!==expected.length||
   report.recordHashMatches!==expected.length||report.eventTimeMatches!==expected.length||
   report.ruby!=='3.2'||report.fluentd!=='1.17.1'||
   report.confAstVerified!==true||report.parserCallbackVerified!==true||
   report.sourceHashVerifiedAgainstEvents!==true||report.nativeUserParserVerified!==true||
   report.targetImportVerified!==false||report.sensorTrafficSent!==false||
   report.rawValuesReturned!==false)untrusted();
 return report as NativeProjectVerificationReport;
}
