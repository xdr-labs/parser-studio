/** P1-AP6 JSONata-compatible simple field-path subset, not an evaluator.
 * No filter, function, wildcard, array, assignment or expression execution.
 */
import type {ParserDraft,SuiteResult} from '../model';
import {compareBrowserSuites} from './autoParserRegression';
import {lookupFieldValue} from '../fieldPaths';
import {toBackendProject} from './backendAdapter';
import {defaultGuidedOptions} from './contract';

export type SafePathReview=
 | {ok:true;candidate:ParserDraft;source:string;target:string;
    contract:'auto-parser.bounded-path.v0.1';approvalRequired:true;
    nativeVerified:false;targetVerified:false}
 | {ok:false;reason:'UNSUPPORTED_EXPRESSION'|'UNTRUSTED_SOURCE'|
    'NOT_PRESENT_IN_ALL_EVENTS'|'MAPPING_CONFLICT'|'BACKEND_UNSUPPORTED'};
const PATH=/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,7}$/;
const UNSAFE=new Set(['constructor','prototype','__proto__']);
/** Only dot-property lookup syntax: $.a.b or a.b, as a safe reviewed mapping path. */
export function prepareBoundedPathCandidate(
 expression:string,source:string,draft:ParserDraft,suite:SuiteResult,
):SafePathReview{
 const fail=(reason:Extract<SafePathReview,{ok:false}>['reason']):SafePathReview=>
  ({ok:false,reason});
 if(typeof expression!=='string'||expression.length>128)return fail('UNSUPPORTED_EXPRESSION');
 const input=expression.trim();
 const normalized=input.startsWith('$.')?input.slice(2):input;
 if(!PATH.test(normalized)||normalized.split('.').some(k=>UNSAFE.has(k)))
  return fail('UNSUPPORTED_EXPRESSION');
 try{compareBrowserSuites(source,suite,suite);}catch{return fail('UNTRUSTED_SOURCE');}
 if(!suite.events.every(event=>{
  if(!event.extracted)return false;
  const item=lookupFieldValue(event.fields,normalized);
  return item.found&&item.value!==undefined&&item.value!==null&&
   typeof item.value!=='object';
 }))return fail('NOT_PRESENT_IN_ALL_EVENTS');
 const target='custom.'+normalized.replace(/\./g,'_');
 const overlaps=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
 if(draft.mappings.some(rule=>rule.source===normalized||overlaps(rule.target,target)))
  return fail('MAPPING_CONFLICT');
 const opts=draft.guided??defaultGuidedOptions();
 const id='simple-path-'+(draft.mappings.length+1);
 const candidate:ParserDraft={...draft,mappings:[...draft.mappings,
   {id,source:normalized,target,type:'string'}],
  guided:{...opts,groups:{...opts.groups,[id]:'vendor_fields'}}};
 if(!toBackendProject(candidate).ok)return fail('BACKEND_UNSUPPORTED');
 return {ok:true,candidate,source:normalized,target,
  contract:'auto-parser.bounded-path.v0.1',approvalRequired:true,
  nativeVerified:false,targetVerified:false};
}
