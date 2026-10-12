/** P1-AP7 explicitly saved, browser-local mapping signatures. No raw samples. */
import type {MappingRule,ParserDraft} from '../model';
import type {CandidateComparison} from './autoParserRegression';
import type {FieldGroup} from './contract';
import {defaultGuidedOptions} from './contract';
import {toBackendProject} from './backendAdapter';

const KEY='parser-studio:approved-patterns:v0.1';
const LIMIT=20;
const SAFE=/^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
const TYPES=new Set(['string','integer','ip','port','boolean','timestamp']);
const GROUPS=new Set(['top_fields','ns_fields','vendor_fields']);
const FAMILIES=new Set(['json','kv','csv','cef','leef','syslog_rfc5424']);
const BANNED=new Set(['__proto__','prototype','constructor']);
export interface ApprovedPattern {
 contract:'auto-parser.approved-mapping.v0.1';
 id:string;family:string;
 mapping:{source:string;target:string;type:MappingRule['type'];group:FieldGroup};
 evidence:{originalEvents:number;holdoutEvents:number;previousPasses:number;
  candidatePasses:number;regressions:0};
 origin:'explicit-browser-user-approval';
 rawLogsIncluded:false;nativeVerified:false;targetVerified:false;
}
export type PatternCandidate=
 | {ok:true;draft:ParserDraft;source:string;target:string}
 | {ok:false;reason:'MISMATCHED_FORMAT'|'DUPLICATE_OR_CONFLICT'|'UNSUPPORTED_BACKEND'|'UNTRUSTED_PATTERN'};
function path(value:unknown){return typeof value==='string'&&value.length<=128&&
 SAFE.test(value)&&value.split('.').every(x=>!BANNED.has(x));}
function exact(value:unknown,keys:string[]):value is Record<string,unknown>{
 return !!value&&typeof value==='object'&&!Array.isArray(value)&&
 Object.keys(value).length===keys.length&&Object.keys(value).every(k=>keys.includes(k));
}
export function validApprovedPattern(raw:unknown):raw is ApprovedPattern{
 if(!exact(raw,['contract','id','family','mapping','evidence','origin','rawLogsIncluded',
   'nativeVerified','targetVerified'])||
  raw.contract!=='auto-parser.approved-mapping.v0.1'||
  typeof raw.id!=='string'||!/^review-[a-f0-9-]{12,40}$/.test(raw.id)||
  !FAMILIES.has(String(raw.family))||
  raw.origin!=='explicit-browser-user-approval'||raw.rawLogsIncluded!==false||
  raw.nativeVerified!==false||raw.targetVerified!==false||
  !exact(raw.mapping,['source','target','type','group'])||
  !path(raw.mapping.source)||!path(raw.mapping.target)||
  !TYPES.has(String(raw.mapping.type))||!GROUPS.has(String(raw.mapping.group))||
  !exact(raw.evidence,['originalEvents','holdoutEvents','previousPasses','candidatePasses','regressions']))return false;
 const e=raw.evidence;
 return [e.originalEvents,e.holdoutEvents,e.previousPasses,e.candidatePasses].every(
  n=>Number.isSafeInteger(n)&&Number(n)>=0&&Number(n)<=500)&&
  Number(e.originalEvents)>=1&&Number(e.holdoutEvents)>=1&&e.regressions===0;
}
function store(storage?:Storage):Storage{
 const active=storage??globalThis.localStorage;
 if(!active)throw new Error('LOCAL_STORAGE_UNAVAILABLE');
 return active;
}
export function readApprovedPatterns(storage?:Storage):ApprovedPattern[]{
 try{
   const raw=store(storage).getItem(KEY);
   if(!raw||raw.length>40_000)return [];
   const data:unknown=JSON.parse(raw);
   if(!Array.isArray(data)||data.length>LIMIT)return [];
   return data.filter(validApprovedPattern).slice(0,LIMIT);
 }catch{return [];}
}
export function saveApprovedMapping(input:{draft:ParserDraft;mapping:MappingRule;
 comparison:CandidateComparison},storage?:Storage):ApprovedPattern{
 const {draft,mapping,comparison}=input;
 const matched=draft.mappings.find(x=>x.id===mapping.id);
 const opts=draft.guided??defaultGuidedOptions();
 const group=opts.groups[mapping.id]??'vendor_fields';
 if(!matched||JSON.stringify(matched)!==JSON.stringify(mapping)||
  !FAMILIES.has(draft.format)||!path(mapping.source)||!path(mapping.target)||
  !TYPES.has(mapping.type)||!GROUPS.has(group)||!toBackendProject(draft).ok||
  comparison.contract!=='auto-parser.candidate-comparison.v0.1'||
  !comparison.acceptedWithoutRegression||comparison.holdoutStatus!=='TESTED'||
  !comparison.holdout||comparison.holdout.sourceCount<1||
  comparison.baseline.regressions!==0||comparison.holdout.regressions!==0||
  comparison.baseline.fieldRemovals!==0||comparison.holdout.fieldRemovals!==0||
  comparison.baseline.typeChanges!==0||comparison.holdout.typeChanges!==0||
  comparison.nativeVerified!==false||comparison.targetVerified!==false){
  throw new Error('Reviewed mapping and independent holdout proof are required.');
 }
 const p:ApprovedPattern={
  contract:'auto-parser.approved-mapping.v0.1',
  id:'review-'+crypto.randomUUID(),family:draft.format,
  mapping:{source:mapping.source,target:mapping.target,type:mapping.type,group},
  evidence:{originalEvents:comparison.baseline.sourceCount,
   holdoutEvents:comparison.holdout.sourceCount,
   previousPasses:comparison.baseline.positiveBefore,
   candidatePasses:comparison.baseline.positiveAfter,regressions:0},
  origin:'explicit-browser-user-approval',rawLogsIncluded:false,
  nativeVerified:false,targetVerified:false,
 };
 if(!validApprovedPattern(p))throw new Error('Untrusted approved pattern');
 const existing=readApprovedPatterns(storage);
 const unique=existing.filter(x=>!(x.family===p.family&&
  x.mapping.source===p.mapping.source&&x.mapping.target===p.mapping.target));
 store(storage).setItem(KEY,JSON.stringify([p,...unique].slice(0,LIMIT)));
 return p;
}
export function prepareApprovedPatternDraft(draft:ParserDraft,pattern:unknown):PatternCandidate{
 if(!validApprovedPattern(pattern))return {ok:false,reason:'UNTRUSTED_PATTERN'};
 if(draft.format!==pattern.family)return {ok:false,reason:'MISMATCHED_FORMAT'};
 const m=pattern.mapping;
 const conflicts=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
 if(draft.mappings.some(x=>x.source===m.source||conflicts(x.target,m.target)))
  return {ok:false,reason:'DUPLICATE_OR_CONFLICT'};
 const opts=draft.guided??defaultGuidedOptions();
 const mapping:MappingRule={id:'reused-'+String(draft.mappings.length+1),
  source:m.source,target:m.target,type:m.type};
 const candidate:ParserDraft={...draft,mappings:[...draft.mappings,mapping],
  guided:{...opts,groups:{...opts.groups,[mapping.id]:m.group}}};
 if(!toBackendProject(candidate).ok)return {ok:false,reason:'UNSUPPORTED_BACKEND'};
 return {ok:true,draft:candidate,source:mapping.source,target:mapping.target};
}

/** Explicit local pattern removal; never changes the live draft or any revision. */
export function forgetApprovedPattern(id:string,storage?:Storage):boolean{
 if(typeof id!=='string'||!/^review-[a-f0-9-]{12,40}$/.test(id))return false;
 try{
   const before=readApprovedPatterns(storage);
   const next=before.filter(entry=>entry.id!==id);
   if(next.length===before.length)return false;
   store(storage).setItem(KEY,JSON.stringify(next));
   return true;
 }catch{return false;}
}
