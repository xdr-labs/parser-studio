/** AP4 deterministic, browser-only candidate comparison.
 * Values and raw event bodies NEVER enter the report or backend requests.
 */
import type {EventResult,ParserDraft,SuiteResult} from '../model';
import {MAX_DATASET_BYTES,MAX_EVENTS,splitEvents} from '../parser';
import {analyzeLogEnvelopes,type EnvelopeEntry} from './autoParserEnvelope';
import {suggestUnmappedFields} from './fieldMappingSuggestions';
import {defaultGuidedOptions} from './contract';
import {toBackendProject} from './backendAdapter';

export type RepairReason='BOUNDARY_AMBIGUOUS'|'EXTRACTION_NO_MATCH'|'TYPE_CONFLICT'|
  'COMPILER_UNSUPPORTED'|'SOURCE_INVALID'|'MAPPING_REVIEW'|'NATIVE_PENDING';
export interface SafeEventDelta {
  line:number;
  family:string;
  before:'PASS'|'REVIEW'|'FAILED';
  after:'PASS'|'REVIEW'|'FAILED';
  addedFields:number;
  removedFields:number;
  typeChanges:number;
  reason:RepairReason;
}
export interface BoundedRegressionReport {
  contract:'auto-parser.regression.v0.1';
  sourceCount:number;
  accounted:number;
  positiveBefore:number;
  positiveAfter:number;
  regressions:number;
  fieldAdditions:number;
  fieldRemovals:number;
  typeChanges:number;
  issues:Array<{reason:RepairReason;count:number}>;
  families:Array<{family:string;count:number;beforePassed:number;afterPassed:number}>;
  events:SafeEventDelta[];
  browserOnly:true;nativeVerified:false;targetVerified:false;
}
export type HoldoutRejectionReason='TOO_SMALL'|'TRAINING_OVERLAP'|'IDENTICAL_TO_TRAINING';
export type HoldoutIndependence=
 | {ok:true;trainingUnique:number;holdoutUnique:number;requiredUnique:number;overlapCount:0}
 | {ok:false;reason:HoldoutRejectionReason;trainingUnique:number;holdoutUnique:number;
     requiredUnique:number;overlapCount:number};
export interface CandidateComparison {
  contract:'auto-parser.candidate-comparison.v0.1';
  baseline:BoundedRegressionReport;
  holdout:BoundedRegressionReport|null;
  holdoutStatus:'NOT_SUPPLIED'|'REJECTED'|'TESTED';
  holdoutIndependence:HoldoutIndependence|null;
  acceptedWithoutRegression:boolean;
  approvalRequired:true;
  nativeVerified:false;targetVerified:false;
}
export type RepairProposal=
 | {ok:true;candidate:ParserDraft;mapping:{source:string;target:string;type:string};
     approvalRequired:true}
 | {ok:false;reason:'INSUFFICIENT_SAMPLE'|'NO_SAFE_CHANGE'|'BACKEND_UNSUPPORTED'};
const SAFE_CODES=new Set(['TYPE_ERROR','INVALID_MAPPING','TARGET_COLLISION','SOURCE_NOT_FOUND',
  'EXTRACTION_FAILED','UNSUPPORTED_FORMAT','ENRICHMENT_TYPE','ENRICHMENT_SOURCE','NO_MAPPINGS']);
function fail(reason:string):never{throw new Error('Cannot compare exact browser evidence: '+reason);}
function audited(source:string,result:SuiteResult){
 if(typeof source!=='string'||!source.trim()||
    new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES||
    !result||result.engine!=='browser-preview'||result.nativeFluentdVerified!==false||
    result.stellarExportVerified!==false||!Array.isArray(result.events))
    fail('source/verification flags are invalid');
 const records=splitEvents(source,'single-line',MAX_EVENTS+1);
 if(!records.length||records.length>MAX_EVENTS||
    result.events.length!==records.length||result.counts?.total!==records.length||
    records.some((item,i)=>item.raw!==result.events[i]?.raw||item.line!==result.events[i]?.line))
    fail('missing, reordered, or mutated source events');
 const expected={matched:0,extracted:0,normalized:0,failures:0,warnings:0};
 for(const event of result.events){
   if(!event||!['pass','fail','warning'].includes(event.status)||
     !Array.isArray(event.diagnostics)||event.diagnostics.length>64||
     !event.diagnostics.every(d=>['error','warning'].includes(d.severity)))
     fail('event status/diagnostics invalid');
   if(event.matched)expected.matched++;
   if(event.extracted)expected.extracted++;
   if(event.normalizedOk)expected.normalized++;
   if(event.status==='fail')expected.failures++;
   if(event.status==='warning')expected.warnings++;
 }
 if(Object.entries(expected).some(([key,n])=>
   result.counts[key as keyof typeof expected]!==n))
   fail('forged aggregate totals');
 return records;
}
const positive=(e:EventResult)=>e.status==='pass'&&e.matched&&e.extracted&&e.normalizedOk;
const status=(e:EventResult):SafeEventDelta['before']=>positive(e)?'PASS':e.status==='fail'?'FAILED':'REVIEW';
// A single FortiGate-style event carries 40+ source fields and the normalized output
// holds each of them under more than one namespace, so 100 leaves was too small and
// made every reviewed fix on such logs fail. The bound only protects the browser from
// pathological input.
export const MAX_NORMALIZED_FIELDS=512;
function shapes(input:unknown):Map<string,string>{
 const result=new Map<string,string>();
 function walk(node:unknown,path:string,depth:number){
   if(depth>8||result.size>MAX_NORMALIZED_FIELDS)return;
   if(node&&typeof node==='object'&&!Array.isArray(node)){
     for(const [k,v] of Object.entries(node)){
       if(k==='constructor'||k==='prototype'||k==='__proto__')continue;
       walk(v,path?path+'.'+k:k,depth+1);
     }
   }else if(path)result.set(path,node===null?'null':Array.isArray(node)?'array':typeof node);
 }
 walk(input,'',0);
 if(result.size>MAX_NORMALIZED_FIELDS)fail('normalized field depth/count exceeded');
 return result;
}
function familyName(item:EnvelopeEntry){return item.envelope+'/'+item.body;}
function reasonFor(event:EventResult,envelope:EnvelopeEntry):RepairReason{
 if(envelope.status==='BOUNDARY_AMBIGUOUS')return 'BOUNDARY_AMBIGUOUS';
 if(envelope.status!=='RECOGNIZED')return 'SOURCE_INVALID';
 if(envelope.envelope==='rfc3164')return 'COMPILER_UNSUPPORTED';
 if(!event.matched||!event.extracted)return 'EXTRACTION_NO_MATCH';
 if(event.diagnostics.some(d=>SAFE_CODES.has(d.code)&&d.code==='TYPE_ERROR'))return 'TYPE_CONFLICT';
 if(!event.normalizedOk||event.status!=='pass')return 'MAPPING_REVIEW';
 return 'NATIVE_PENDING';
}
interface ScopedReplacement {oldTarget:string;newTarget:string}

/** Resolve the actual browser-normalized field location before comparing one
 * AI-suggested mapping correction. Vendor fields are nested under the exact
 * source draft's manufacturer name; top and namespace fields are at the root.
 * Never infer a dotted path from a user-facing field label alone.
 */
export function normalizedMappingOutputPath(draft:ParserDraft,mappingId:string):string{
 const mapped=draft.mappings.find(item=>item.id===mappingId);
 if(!mapped)fail('mapping identity is missing');
 const group=draft.guided?.groups[mappingId]??'vendor_fields';
 if(group!=='vendor_fields'&&group!=='top_fields'&&group!=='ns_fields')
   fail('mapping field group is invalid');
 if(group!=='vendor_fields')return mapped.target;
 const vendor=draft.vendor.trim()||'vendor';
 return vendor+'.'+mapped.target;
}
/** Exact source identity, all-event accounting, no field names or values in output. */
function compareBrowserSuitesInternal(source:string,before:SuiteResult,after:SuiteResult,
 scope?:ScopedReplacement):BoundedRegressionReport{
 audited(source,before);audited(source,after);
 const ledger=analyzeLogEnvelopes(source,'single-line');
 if(ledger.status!=='READY'||ledger.accounted!==ledger.sourceCount||
   ledger.sourceCount!==before.events.length)fail('source envelope ledger incomplete');
 const eventChanges:SafeEventDelta[]=[];
 const issues=new Map<RepairReason,number>();
 const families=new Map<string,{family:string;count:number;beforePassed:number;afterPassed:number}>();
 let regressions=0,fieldAdditions=0,fieldRemovals=0,typeChanges=0;
 for(let i=0;i<before.events.length;i++){
   const b=before.events[i]!,a=after.events[i]!,entry=ledger.events[i]!;
   const prev=shapes(b.normalized),next=shapes(a.normalized);
   let added=0,removed=0,changed=0;
   const scopedOk=!scope||(
     prev.has(scope.oldTarget)&&next.has(scope.newTarget)&&
     prev.get(scope.oldTarget)===next.get(scope.newTarget)&&
     (scope.oldTarget===scope.newTarget||!next.has(scope.oldTarget))
   );
   for(const [key,value] of prev){
     if(scope&&key===scope.oldTarget){
       if(scope.oldTarget===scope.newTarget&&!next.has(key))removed++;
       continue;
     }
     if(!next.has(key))removed++;else if(next.get(key)!==value)changed++;
   }
   for(const key of next.keys()){
     if(scope&&scope.oldTarget!==scope.newTarget&&key===scope.newTarget)continue;
     if(!prev.has(key))added++;
   }
   // Scoped correction needs the exact old/new typed field in every source
   // event, even when unrelated unmapped fields made the baseline a REVIEW.
   // Otherwise a renamed but type-mutated vendor value can look like PASS.
   const regression=(scope!==undefined&&!scopedOk)||
     (positive(b)&&(!positive(a)||removed>0||changed>0));
   if(regression)regressions++;
   const family=familyName(entry);
   const f=families.get(family)??{family,count:0,beforePassed:0,afterPassed:0};
   f.count++;if(positive(b))f.beforePassed++;if(positive(a))f.afterPassed++;
   families.set(family,f);
   const reason=reasonFor(a,entry);
   issues.set(reason,(issues.get(reason)??0)+1);
   fieldAdditions+=added;fieldRemovals+=removed;typeChanges+=changed;
   eventChanges.push({line:entry.line,family,before:status(b),after:status(a),
     addedFields:added,removedFields:removed,typeChanges:changed,reason});
 }
 return {contract:'auto-parser.regression.v0.1',sourceCount:ledger.sourceCount,
   accounted:eventChanges.length,positiveBefore:before.events.filter(positive).length,
   positiveAfter:after.events.filter(positive).length,regressions,fieldAdditions,
   fieldRemovals,typeChanges,issues:[...issues].map(([reason,count])=>({reason,count})),
   families:[...families.values()],events:eventChanges,browserOnly:true,
   nativeVerified:false,targetVerified:false};
}
export function compareBrowserSuites(source:string,before:SuiteResult,after:SuiteResult):BoundedRegressionReport{
 return compareBrowserSuitesInternal(source,before,after);
}
function recordIdentity(raw:string):string{return raw.trim();}
export function assessHoldoutIndependence(trainingSource:string,holdoutSource:string):HoldoutIndependence{
 const trainingRecords=splitEvents(trainingSource,'single-line',MAX_EVENTS+1);
 const holdoutRecords=splitEvents(holdoutSource,'single-line',MAX_EVENTS+1);
 const trainingSet=new Set(trainingRecords.map(item=>recordIdentity(item.raw)));
 const holdoutSet=new Set(holdoutRecords.map(item=>recordIdentity(item.raw)));
 const trainingUnique=trainingSet.size,holdoutUnique=holdoutSet.size;
 const requiredUnique=Math.max(2,Math.min(5,Math.ceil(trainingUnique/4)));
 const overlapCount=[...holdoutSet].filter(item=>trainingSet.has(item)).length;
 const identical=trainingUnique===holdoutUnique&&trainingUnique>0&&
   [...trainingSet].every(item=>holdoutSet.has(item));
 if(identical)return {ok:false,reason:'IDENTICAL_TO_TRAINING',trainingUnique,holdoutUnique,
   requiredUnique,overlapCount};
 if(overlapCount>0)return {ok:false,reason:'TRAINING_OVERLAP',trainingUnique,holdoutUnique,
   requiredUnique,overlapCount};
 if(holdoutUnique<requiredUnique)return {ok:false,reason:'TOO_SMALL',trainingUnique,holdoutUnique,
   requiredUnique,overlapCount:0};
 return {ok:true,trainingUnique,holdoutUnique,requiredUnique,overlapCount:0};
}
type CandidateInput={source:string;baseline:SuiteResult;candidate:SuiteResult;
 holdout?:{source:string;baseline:SuiteResult;candidate:SuiteResult}};
function compareCandidateInternal(input:CandidateInput,scope?:ScopedReplacement):CandidateComparison{
 const baseline=compareBrowserSuitesInternal(input.source,input.baseline,input.candidate,scope);
 const holdoutIndependence=input.holdout?
   assessHoldoutIndependence(input.source,input.holdout.source):null;
 if(holdoutIndependence&&!holdoutIndependence.ok){
   return {contract:'auto-parser.candidate-comparison.v0.1',baseline,holdout:null,
     holdoutStatus:'REJECTED',holdoutIndependence,acceptedWithoutRegression:false,
     approvalRequired:true,nativeVerified:false,targetVerified:false};
 }
 const holdout=input.holdout?compareBrowserSuitesInternal(input.holdout.source,
   input.holdout.baseline,input.holdout.candidate,scope):null;
 return {contract:'auto-parser.candidate-comparison.v0.1',baseline,holdout,
   holdoutStatus:holdout?'TESTED':'NOT_SUPPLIED',holdoutIndependence,
   acceptedWithoutRegression:baseline.regressions===0&&baseline.fieldRemovals===0&&
    baseline.typeChanges===0&&(!holdout||holdout.regressions===0&&
      holdout.fieldRemovals===0&&holdout.typeChanges===0),
   approvalRequired:true,nativeVerified:false,targetVerified:false};
}
export function compareCandidate(input:CandidateInput):CandidateComparison{
 return compareCandidateInternal(input);
}
export function compareMappingCorrectionCandidate(input:CandidateInput,
 scope:ScopedReplacement):CandidateComparison{
 // The real normalized vendor namespace can precede a separately bounded
 // mapping target. Allow the combined path, not arbitrary unbounded scopes.
 if(!scope.oldTarget||!scope.newTarget||scope.oldTarget.length>256||scope.newTarget.length>256)
  fail('invalid scoped mapping replacement');
 return compareCandidateInternal(input,scope);
}
/** A single conservative field suggestion; no candidate is ever auto-applied. */
export function proposeReviewableMapping(source:string,draft:ParserDraft,suite:SuiteResult):RepairProposal{
 try{audited(source,suite);}catch{return {ok:false,reason:'INSUFFICIENT_SAMPLE'};}
 if(suite.events.length<2||suite.events.some(e=>!e.extracted||!e.matched))
   return {ok:false,reason:'INSUFFICIENT_SAMPLE'};
 const suggestions=suggestUnmappedFields(suite.events.map(e=>e.fields),draft);
 const first=suggestions.find(s=>suite.events.every(e=>{
   const parts=s.source.split('.');let value:unknown=e.fields;
   for(const part of parts){
     if(!value||typeof value!=='object'||Array.isArray(value)||
       !Object.prototype.hasOwnProperty.call(value,part))return false;
     value=(value as Record<string,unknown>)[part];
   }
   return value!==undefined&&value!==null&&typeof value!=='object';
 }));
 if(!first)return {ok:false,reason:'NO_SAFE_CHANGE'};
 const option=draft.guided??defaultGuidedOptions();
 const mapping={id:'repair-'+(draft.mappings.length+1),source:first.source,
   target:first.target,type:first.type};
 const candidate:ParserDraft={...draft,mappings:[...draft.mappings,mapping],
   guided:{...option,groups:{...option.groups,[mapping.id]:first.group}}};
 if(!toBackendProject(candidate).ok)return {ok:false,reason:'BACKEND_UNSUPPORTED'};
 return {ok:true,candidate,mapping:{source:first.source,target:first.target,type:first.type},
   approvalRequired:true};
}
