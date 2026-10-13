/** P0-AP3 UI-owned ParserRecipe v0.2 review adapter.
 *
 * The current backend only compiles ParserProject v0.1. This is a bounded,
 * target-independent, strictly declarative plan, NOT executable Ruby or a
 * claim of native parsing. The only compatibility claim is a no-loss
 * projection of the *same validated v0.1 project metadata*.
 */
import type {ParserDraft,SuiteResult} from '../model';
import {MAX_DATASET_BYTES,MAX_EVENTS,splitEvents} from '../parser';
import {toBackendProject,type BackendParserProject} from './backendAdapter';
import {defaultGuidedOptions} from './contract';

export type ReviewStage=
 | {op:'split_event';boundary:'single-line'}
 | {op:'unwrap_syslog';version:1|3164;mode:'strict_header'}
 | {op:'parse_json'|'parse_kv'|'parse_cef'|'parse_leef'}
 | {op:'parse_csv';columns:string[];delimiter:','|';'|'\t'}
 | {op:'map_field';source:string;target:string;data_type:'string'|'integer'|'ip'|'port'|'boolean'|'date';group:'top_fields'|'ns_fields'|'vendor_fields'}
 | {op:'cast_type';target:string;data_type:'integer'|'ip'|'port'|'boolean'|'date';timezone?:'UTC'}
 | {op:'classify';defaultIndex:'session'|'threat'|'syslog'|'winlogevent';rules:Array<{field:string;operator:'equals';value:string;index:'session'|'threat'|'syslog'|'winlogevent'}>}
 | {op:'fallback_unparsed';mode:'retain_unparsed'};
export interface ParserRecipeV2{
  contract:'parser-studio.recipe.v0.2';
  schemaRevision:'0.2';
  compilerMode:'REVIEW_ONLY';
  projectId:string;
  sourceFormat:'json'|'kv'|'csv'|'syslog_rfc3164'|'syslog_rfc5424'|'cef'|'leef';
  bodyFormat:'json'|'kv'|'csv'|'cef'|'leef';
  sample:{sha256:string;events:number};
  stages:ReviewStage[];
  nativeVerified:false;
  targetVerified:false;
}
export interface RecipeLossReport {
 status:'V01_SNAPSHOT_PRESERVED';lossyOperations:0;
 v02CompilerAvailable:false;nativeUserParserVerified:false;
 targetImportVerified:false;rawLogIncluded:false;
}
export type RecipeReview=
 | {ok:true;recipe:ParserRecipeV2;legacyProject:BackendParserProject;
    lossReport:RecipeLossReport;compatibility:'V01_METADATA_ROUNDTRIP';
    v02CompilerAvailable:false}
 | {ok:false;reason:'SOURCE_LIMIT'|'SAMPLE_MISMATCH'|'UNTRUSTED_PREVIEW'|
    'SAMPLE_PREVIEW_INCOMPLETE'|'COMPILER_UNSUPPORTED'|'MODEL_REVIEW_REQUIRED'};
const SHA=/^[a-f0-9]{64}$/;
const PATH=/^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
const UNSAFE=new Set(['constructor','prototype','__proto__']);
const INDICES=['session','threat','syslog','winlogevent'];
const TYPES=['string','integer','ip','port','boolean','date'];
const GROUPS=['top_fields','ns_fields','vendor_fields'];
const PARSERS=['parse_json','parse_kv','parse_cef','parse_leef','parse_csv'];
const exact=(value:unknown,keys:string[])=>{
 if(!value||typeof value!=='object'||Array.isArray(value))return false;
 const actual=Object.keys(value as object).sort();
 return actual.length===keys.length&&
   actual.every((key,i)=>key===[...keys].sort()[i]);
};
const safePath=(v:unknown)=>typeof v==='string'&&v.length>=1&&v.length<=128&&
 PATH.test(v)&&v.split('.').every(x=>!UNSAFE.has(x));
const safeValue=(v:unknown)=>typeof v==='string'&&v.length<=128&&
 !/[\r\n\u0000-\u001f\u007f]/.test(v);
function validateStage(input:unknown):input is ReviewStage{
 if(!input||typeof input!=='object'||Array.isArray(input))return false;
 const s=input as Record<string,unknown>;
 switch(s.op){
  case 'split_event':return exact(s,['op','boundary'])&&s.boundary==='single-line';
  case 'unwrap_syslog':return exact(s,['op','version','mode'])&&
   [1,3164].includes(s.version as number)&&s.mode==='strict_header';
  case 'parse_json':case 'parse_kv':case 'parse_cef':case 'parse_leef':
   return exact(s,['op']);
  case 'parse_csv':return exact(s,['op','columns','delimiter'])&&
   Array.isArray(s.columns)&&s.columns.length>=1&&s.columns.length<=100&&
   s.columns.every(safePath)&&new Set(s.columns).size===s.columns.length&&
   [',',';','\t'].includes(String(s.delimiter));
  case 'map_field':return exact(s,['op','source','target','data_type','group'])&&
   safePath(s.source)&&safePath(s.target)&&TYPES.includes(String(s.data_type))&&
   GROUPS.includes(String(s.group));
  case 'cast_type':return (
    exact(s,['op','target','data_type'])||exact(s,['op','target','data_type','timezone'])
   )&&safePath(s.target)&&TYPES.slice(1).includes(String(s.data_type))&&
   (s.data_type==='date'?s.timezone==='UTC':s.timezone===undefined);
  case 'classify':return exact(s,['op','defaultIndex','rules'])&&
   INDICES.includes(String(s.defaultIndex))&&Array.isArray(s.rules)&&
   s.rules.length<=24&&s.rules.every(x=>{
     if(!exact(x,['field','operator','value','index']))return false;
     const r=x as {field:unknown;operator:unknown;value:unknown;index:unknown};
     return safePath(r.field)&&r.operator==='equals'&&safeValue(r.value)&&
       INDICES.includes(String(r.index));
   });
  case 'fallback_unparsed':return exact(s,['op','mode'])&&s.mode==='retain_unparsed';
  default:return false;
 }
}
export function validateReviewableRecipe(raw:unknown):raw is ParserRecipeV2{
 if(!exact(raw,['contract','schemaRevision','compilerMode','projectId',
  'sourceFormat','bodyFormat','sample','stages','nativeVerified','targetVerified']))return false;
 const r=raw as ParserRecipeV2;
 if(r.contract!=='parser-studio.recipe.v0.2'||r.schemaRevision!=='0.2'||
    r.compilerMode!=='REVIEW_ONLY'||r.nativeVerified!==false||
    r.targetVerified!==false||
    typeof r.projectId!=='string'||!/^draft-[a-z][a-z0-9_]{2,47}$/.test(r.projectId)||
    !['json','kv','csv','cef','leef','syslog_rfc3164','syslog_rfc5424'].includes(r.sourceFormat)||
    !['json','kv','csv','cef','leef'].includes(r.bodyFormat)||
    (!['syslog_rfc3164','syslog_rfc5424'].includes(r.sourceFormat)&&r.sourceFormat!==r.bodyFormat)||
    (['syslog_rfc3164','syslog_rfc5424'].includes(r.sourceFormat)&&r.bodyFormat==='csv')||
    !exact(r.sample,['sha256','events'])||!SHA.test(r.sample.sha256)||
    !Number.isSafeInteger(r.sample.events)||r.sample.events<1||r.sample.events>MAX_EVENTS||
    !Array.isArray(r.stages)||r.stages.length<4||r.stages.length>125||
    !r.stages.every(validateStage)||
    r.stages[0]?.op!=='split_event'||
    r.stages.at(-1)?.op!=='fallback_unparsed')return false;
 const stages=r.stages;
 let i=1;
 if(['syslog_rfc3164','syslog_rfc5424'].includes(r.sourceFormat)){
   const unwrapped=stages[i++];
   if(unwrapped?.op!=='unwrap_syslog'||
     unwrapped.version!==(r.sourceFormat==='syslog_rfc3164'?3164:1)||
     unwrapped.mode!=='strict_header')return false;
 }else if(stages[i]?.op==='unwrap_syslog')return false;
 const parse=stages[i++];
 const expected='parse_'+r.bodyFormat;
 if(!parse||!PARSERS.includes(parse.op)||parse.op!==expected)return false;
 const targets=new Set<string>();
 let mapCount=0;
 while(stages[i]?.op==='map_field'){
   const m=stages[i] as Extract<ReviewStage,{op:'map_field'}>;
   if(targets.has(m.target))return false;
   targets.add(m.target);mapCount++;i++;
   if(m.data_type!=='string'){
     const cast=stages[i] as ReviewStage|undefined;
     if(!cast||cast.op!=='cast_type'||cast.target!==m.target||
       cast.data_type!==m.data_type)return false;
     i++;
   }
 }
 if(mapCount>50)return false;
 if(stages[i++]?.op!=='classify')return false;
 if(i!==stages.length-1||stages[i]?.op!=='fallback_unparsed')return false;
 return true;
}
async function sha256(source:string):Promise<string>{
 if(!globalThis.crypto?.subtle)throw new Error('Secure browser SHA-256 is required.');
 const raw=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(source));
 return [...new Uint8Array(raw)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
export async function buildReviewableRecipe(
 source:string,draft:ParserDraft,suite:SuiteResult|undefined,
):Promise<RecipeReview>{
 const fail=(reason:Extract<RecipeReview,{ok:false}>['reason']):RecipeReview=>
  ({ok:false,reason});
 if(typeof source!=='string'||!source.trim()||
   new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES||
   draft.guided?.eventBoundary==='blank-line')return fail('SOURCE_LIMIT');
 const records=splitEvents(source,'single-line',MAX_EVENTS+1);
 if(!records.length||records.length>MAX_EVENTS)return fail('SOURCE_LIMIT');
 if(!suite||suite.engine!=='browser-preview'||suite.nativeFluentdVerified!==false||
   suite.stellarExportVerified!==false||!Array.isArray(suite.events))return fail('UNTRUSTED_PREVIEW');
 if(suite.events.length!==records.length||suite.counts.total!==records.length||
   records.some((rec,i)=>rec.raw!==suite.events[i]?.raw||rec.line!==suite.events[i]?.line))
   return fail('SAMPLE_MISMATCH');
 if(suite.counts.extracted!==records.length||
    suite.counts.matched!==records.length||
    suite.counts.normalized!==records.length||
    suite.counts.failures>0)return fail('SAMPLE_PREVIEW_INCOMPLETE');
 if(!['json','kv','csv','cef','leef','syslog_rfc3164','syslog_rfc5424'].includes(draft.format))
   return fail('COMPILER_UNSUPPORTED');
 const project=toBackendProject(draft);
 if(!project.ok)return fail('MODEL_REVIEW_REQUIRED');
 const sourceFormat=draft.format as ParserRecipeV2['sourceFormat'];
 if(['syslog_rfc3164','syslog_rfc5424'].includes(sourceFormat)&&
    (draft.syslogBodyFormat??'raw')==='raw')
   return fail('COMPILER_UNSUPPORTED');
 const stages:ReviewStage[]=[{op:'split_event',boundary:'single-line'}];
 if(['syslog_rfc3164','syslog_rfc5424'].includes(sourceFormat))
   stages.push({op:'unwrap_syslog',
     version:sourceFormat==='syslog_rfc3164'?3164:1,mode:'strict_header'});
 const body=['syslog_rfc3164','syslog_rfc5424'].includes(sourceFormat)?
   draft.syslogBodyFormat!:sourceFormat;
 if(body==='csv'){
   stages.push({op:'parse_csv',columns:project.project.extraction.format==='csv'
     ?project.project.extraction.csvColumns:[],delimiter:project.project.extraction.format==='csv'
       ?project.project.extraction.csvDelimiter:','});
 }else if(['json','kv','cef','leef'].includes(body)){
   stages.push({op:('parse_'+body) as 'parse_json'|'parse_kv'|'parse_cef'|'parse_leef'});
 }else return fail('COMPILER_UNSUPPORTED');
 const groups=(draft.guided??defaultGuidedOptions()).groups;
 for(const mapping of draft.mappings){
   const group=groups[mapping.id]??'vendor_fields';
   const data_type=mapping.type==='timestamp'?'date':mapping.type;
   if(!TYPES.includes(data_type)||!GROUPS.includes(group))return fail('MODEL_REVIEW_REQUIRED');
   stages.push({op:'map_field',source:mapping.source,target:mapping.target,
     data_type:data_type as Extract<ReviewStage,{op:'map_field'}>['data_type'],group});
   if(data_type!=='string'){
     stages.push({op:'cast_type',target:mapping.target,
       data_type:data_type as Extract<ReviewStage,{op:'cast_type'}>['data_type'],
       ...(data_type==='date'?{timezone:'UTC' as const}:{})});
   }
 }
 stages.push({op:'classify',
   defaultIndex:project.project.classification.defaultIndex,
   rules:project.project.classification.rules});
 stages.push({op:'fallback_unparsed',mode:'retain_unparsed'});
 let digest:string;
 try{digest=await sha256(source);}catch{return fail('UNTRUSTED_PREVIEW');}
 const recipe:ParserRecipeV2={contract:'parser-studio.recipe.v0.2',
   schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
   projectId:project.project.projectId,sourceFormat,
   bodyFormat:body as ParserRecipeV2['bodyFormat'],
   sample:{sha256:digest,events:records.length},stages,
   nativeVerified:false,targetVerified:false};
 if(!validateReviewableRecipe(recipe))return fail('MODEL_REVIEW_REQUIRED');
 return {ok:true,recipe,legacyProject:project.project,
   lossReport:{status:'V01_SNAPSHOT_PRESERVED',lossyOperations:0,
     v02CompilerAvailable:false,nativeUserParserVerified:false,
     targetImportVerified:false,rawLogIncluded:false},
   compatibility:'V01_METADATA_ROUNDTRIP',v02CompilerAvailable:false};
}
