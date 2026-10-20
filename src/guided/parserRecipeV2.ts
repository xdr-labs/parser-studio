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
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {sha256Utf8Hex} from '../sha256';
import {validatePreviewRegexPattern} from '../regexSafety';
import {isGenericStructuralProfile,type GenericStructuralProfile} from '../genericStructuralProfiles';

export type ReviewStage=
 | {op:'split_event';boundary:'single-line'|'blank-line'}
 | {op:'unwrap_syslog';version:1|3164;mode:'strict_header'}
 | {op:'dispatch_family';families:Array<'json'|'kv'|'cef'|'leef'|'rfc5424_cef'|'rfc5424_leef'|'rfc3164_kv'|'rfc5424_json'|'rfc5424_kv'|'rfc3164_cef'|'rfc3164_leef'|'csv'>;mode:'strict_prefix'}
 | {op:'parse_json'|'parse_kv'|'parse_cef'|'parse_leef'|'parse_java_stacktrace'}
 | {op:'parse_generic_structural';profile?:GenericStructuralProfile}
 | {op:'parse_regex';pattern:string}
 | {op:'parse_csv';columns:string[];delimiter:','|';'|'\t'}
 | {op:'map_field';source:string;target:string;data_type:'string'|'integer'|'ip'|'port'|'boolean'|'date';group:'top_fields'|'ns_fields'|'vendor_fields'}
 | {op:'cast_type';target:string;data_type:'integer'|'ip'|'port'|'boolean'|'date';timezone?:'UTC'}
 | {op:'split_field';source:string;delimiter:string;targets:string[]}
 | {op:'merge_fields';sources:string[];delimiter:string;target:string}
 | {op:'classify';defaultIndex:'session'|'threat'|'syslog'|'winlogevent';rules:Array<{field:string;operator:'equals';value:string;index:'session'|'threat'|'syslog'|'winlogevent'}>}
 | {op:'fallback_unparsed';mode:'retain_unparsed'};
export interface ParserRecipeV2{
  contract:'parser-studio.recipe.v0.2';
  schemaRevision:'0.2';
  compilerMode:'REVIEW_ONLY';
  projectId:string;
  sourceFormat:'json'|'kv'|'csv'|'syslog_rfc3164'|'syslog_rfc5424'|'cef'|'leef'|'mixed'|'java_stacktrace'|'regex'|'generic_structural';
  bodyFormat:'json'|'kv'|'csv'|'cef'|'leef'|'mixed'|'java_stacktrace'|'regex'|'generic_structural';
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
const PARSERS=['parse_json','parse_kv','parse_cef','parse_leef','parse_csv','parse_java_stacktrace','parse_regex','parse_generic_structural'];
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
const safeDelimiter=(v:unknown)=>typeof v==='string'&&v.length>=1&&v.length<=8&&
 !/[\u0000-\u001f\u007f]/.test(v);
const overlaps=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
function validateStage(input:unknown):input is ReviewStage{
 if(!input||typeof input!=='object'||Array.isArray(input))return false;
 const s=input as Record<string,unknown>;
 switch(s.op){
  case 'split_event':return exact(s,['op','boundary'])&&['single-line','blank-line'].includes(s.boundary as string);
  case 'dispatch_family':return exact(s,['op','families','mode'])&&
    s.mode==='strict_prefix'&&Array.isArray(s.families)&&
    s.families.length>=2&&s.families.length<=4&&
    new Set(s.families).size===s.families.length&&
    s.families.every(f=>['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef','csv'].includes(f));
  case 'unwrap_syslog':return exact(s,['op','version','mode'])&&
   [1,3164].includes(s.version as number)&&s.mode==='strict_header';
  case 'parse_json':case 'parse_kv':case 'parse_cef':case 'parse_leef':case 'parse_java_stacktrace':
   return exact(s,['op']);
  case 'parse_generic_structural':return exact(s,['op'])||
   (exact(s,['op','profile'])&&isGenericStructuralProfile(s.profile));
  case 'parse_regex':return exact(s,['op','pattern'])&&
   typeof s.pattern==='string'&&validatePreviewRegexPattern(s.pattern)===null;
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
  case 'split_field':return exact(s,['op','source','delimiter','targets'])&&safePath(s.source)&&
   safeDelimiter(s.delimiter)&&Array.isArray(s.targets)&&s.targets.length>=2&&s.targets.length<=8&&
   new Set(s.targets).size===s.targets.length&&s.targets.every(safePath);
  case 'merge_fields':return exact(s,['op','sources','delimiter','target'])&&Array.isArray(s.sources)&&
   s.sources.length>=2&&s.sources.length<=8&&new Set(s.sources).size===s.sources.length&&
   s.sources.every(safePath)&&safeDelimiter(s.delimiter)&&safePath(s.target);
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
    !['json','kv','csv','cef','leef','syslog_rfc3164','syslog_rfc5424','mixed','java_stacktrace','regex','generic_structural'].includes(r.sourceFormat)||
    !['json','kv','csv','cef','leef','mixed','java_stacktrace','regex','generic_structural'].includes(r.bodyFormat)||
    (!['syslog_rfc3164','syslog_rfc5424'].includes(r.sourceFormat)&&r.sourceFormat!==r.bodyFormat)||
    (r.sourceFormat==='mixed'&&r.bodyFormat!=='mixed')||
    (['syslog_rfc3164','syslog_rfc5424'].includes(r.sourceFormat)&&r.bodyFormat==='csv')||
    !exact(r.sample,['sha256','events'])||!SHA.test(r.sample.sha256)||
    !Number.isSafeInteger(r.sample.events)||r.sample.events<1||r.sample.events>MAX_EVENTS||
    !Array.isArray(r.stages)||r.stages.length<4||r.stages.length>125||
    !r.stages.every(validateStage)||
    r.stages[0]?.op!=='split_event'||
    (r.stages[0].boundary==='blank-line'&&
      !(['json','java_stacktrace'].includes(r.sourceFormat)&&r.bodyFormat===r.sourceFormat))||
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
 if(r.sourceFormat==='mixed'){
   if(!parse||parse.op!=='dispatch_family'||parse.mode!=='strict_prefix'||
      parse.families.length<2||parse.families.length>4)return false;
 }else{
   const expected='parse_'+r.bodyFormat;
   if(!parse||!PARSERS.includes(parse.op)||parse.op!==expected)return false;
 }
 const targets=new Set<string>();
 const normalizedTypes=new Map<string,string>();
 let mapCount=0;
 while(stages[i]?.op==='map_field'){
   const m=stages[i] as Extract<ReviewStage,{op:'map_field'}>;
   if([...targets].some(target=>overlaps(target,m.target)))return false;
   targets.add(m.target);normalizedTypes.set(m.target,m.data_type);mapCount++;i++;
   if(m.data_type!=='string'){
     const cast=stages[i] as ReviewStage|undefined;
     if(!cast||cast.op!=='cast_type'||cast.target!==m.target||
       cast.data_type!==m.data_type)return false;
     i++;
   }
 }
 if(mapCount>60)return false;
 let enrichmentCount=0;
 while(true){
   const stage=stages[i];
   if(!stage||(stage.op!=='split_field'&&stage.op!=='merge_fields'))break;
   if(++enrichmentCount>64)return false;
   if(stage.op==='split_field'){
     if(normalizedTypes.get(stage.source)!=='string'||
        stage.targets.some(target=>[...targets].some(existing=>overlaps(existing,target))))return false;
     for(const target of stage.targets){targets.add(target);normalizedTypes.set(target,'string');}
   }else{
     if(stage.sources.some(source=>normalizedTypes.get(source)!=='string')||
        [...targets].some(existing=>overlaps(existing,stage.target)))return false;
     targets.add(stage.target);normalizedTypes.set(stage.target,'string');
   }
   i++;
 }
 const classify=stages[i++];
 if(classify?.op!=='classify'||classify.rules.some(rule=>!normalizedTypes.has(rule.field)))return false;
 if(i!==stages.length-1||stages[i]?.op!=='fallback_unparsed')return false;
 return true;
}
async function sha256(source:string):Promise<string>{return sha256Utf8Hex(source);}
export async function buildReviewableRecipe(
 source:string,draft:ParserDraft,suite:SuiteResult|undefined,
):Promise<RecipeReview>{
 const fail=(reason:Extract<RecipeReview,{ok:false}>['reason']):RecipeReview=>
  ({ok:false,reason});
 const boundary=draft.guided?.eventBoundary??'single-line';
 const framed=boundary==='blank-line'&&
   draft.guided?.receiver.protocols.length===1&&
   draft.guided?.receiver.protocols[0]==='tcp'&&(
     (draft.format==='json'&&draft.guided.receiver.framing==='blank_line_json')||
     (draft.format==='java_stacktrace'&&draft.guided.receiver.framing==='blank_line_java')
   );
 if(typeof source!=='string'||!source.trim()||
   new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES||
   (boundary!=='single-line'&&!framed))return fail('SOURCE_LIMIT');
 if(draft.format==='java_stacktrace'&&source.includes('\r'))
   return fail('SOURCE_LIMIT');
 const records=splitEvents(source,boundary,MAX_EVENTS+1);
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
 if(!['json','kv','csv','cef','leef','syslog_rfc3164','syslog_rfc5424','mixed','java_stacktrace','regex','generic_structural'].includes(draft.format))
   return fail('COMPILER_UNSUPPORTED');
 const project=toBackendProject(draft);
 if(!project.ok)return fail('MODEL_REVIEW_REQUIRED');
 const sourceFormat=draft.format as ParserRecipeV2['sourceFormat'];
 if(sourceFormat==='mixed'){
   const requested=draft.mixedFormats??[];
   const recorded=new Set<string>();
   if(requested.length<2||requested.length>4||
      new Set(requested).size!==requested.length||
      !requested.every(f=>['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef','csv'].includes(f)))
     return fail('COMPILER_UNSUPPORTED');
   const families=analyzeLogEnvelopes(source,'single-line');
   if(families.unsupported>0||families.events.length!==records.length)
     return fail('SAMPLE_MISMATCH');
   for(const [index,row] of records.entries()){
     // Recheck independent strict browser envelope/body detection per event.
     const family=families.events[index];
     const kind=family?.status==='RECOGNIZED'&&
       family.envelope==='rfc5424'&&['cef','leef','json','kv'].includes(family.body)?
         'rfc5424_'+family.body:
       family?.status==='RECOGNIZED'&&family.envelope==='rfc3164'&&['kv','cef','leef'].includes(family.body)?
         'rfc3164_'+family.body:
       family?.status==='RECOGNIZED'&&family.envelope==='none'?family.body:null;
     if(!kind||!requested.includes(kind as typeof requested[number])||
       (kind.startsWith('rfc5424_')&&!/^<\d{1,3}>1 /.test(row.raw))||
       (kind.startsWith('rfc3164_')&&!/^<\d{1,3}>[A-Z][a-z]{2} /.test(row.raw)))
       return fail('SAMPLE_MISMATCH');
     recorded.add(kind);
   }
   if(recorded.size!==requested.length)return fail('MODEL_REVIEW_REQUIRED');
 }
 if(['syslog_rfc3164','syslog_rfc5424'].includes(sourceFormat)&&
    (draft.syslogBodyFormat??'raw')==='raw')
   return fail('COMPILER_UNSUPPORTED');
 const stages:ReviewStage[]=[{op:'split_event',boundary}];
 if(['syslog_rfc3164','syslog_rfc5424'].includes(sourceFormat))
   stages.push({op:'unwrap_syslog',
     version:sourceFormat==='syslog_rfc3164'?3164:1,mode:'strict_header'});
 const body=sourceFormat==='mixed'?'mixed':
   ['syslog_rfc3164','syslog_rfc5424'].includes(sourceFormat)?
   draft.syslogBodyFormat!:sourceFormat;
 if(body==='mixed'){
   stages.push({op:'dispatch_family',families:[...(draft.mixedFormats??[])],
     mode:'strict_prefix'});
 }else if(body==='csv'){
   stages.push({op:'parse_csv',columns:project.project.extraction.format==='csv'
     ?project.project.extraction.csvColumns:[],delimiter:project.project.extraction.format==='csv'
       ?project.project.extraction.csvDelimiter:','});
 }else if(body==='regex'){
   const extraction=project.project.extraction;
   if(!('pattern' in extraction)||typeof extraction.pattern!=='string'||
      validatePreviewRegexPattern(extraction.pattern)!==null)
     return fail('COMPILER_UNSUPPORTED');
   stages.push({op:'parse_regex',pattern:extraction.pattern});
 }else if(body==='generic_structural'){
   stages.push({op:'parse_generic_structural',
     ...(draft.genericStructuralProfile?{profile:draft.genericStructuralProfile}:{})});
 }else if(['json','kv','cef','leef','java_stacktrace'].includes(body)){
   stages.push({op:('parse_'+body) as 'parse_json'|'parse_kv'|'parse_cef'|'parse_leef'|'parse_java_stacktrace'});
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
 for(const enrichment of project.project.enrichment??[]){
   if(enrichment.operator==='split_field')stages.push({op:'split_field',source:enrichment.source,
     delimiter:enrichment.delimiter,targets:[...enrichment.targets]});
   else if(enrichment.operator==='merge_fields')stages.push({op:'merge_fields',sources:[...enrichment.sources],
     delimiter:enrichment.delimiter,target:enrichment.target});
   else return fail('MODEL_REVIEW_REQUIRED');
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
