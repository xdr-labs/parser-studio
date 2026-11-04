/** P0-AP3: exact, strict staged ParserRecipe v0.2 -> already-reviewed v0.1
 * compiler subset. This module does not execute instructions from the recipe.
 * No raw source logs are accepted or persisted; no native/target PASS implied.
 */
import {createHash} from "node:crypto";
import {Ajv} from "ajv";
import recipeSchema from "../schema/parser-recipe.v0.2.schema.json" with {type:"json"};
import {canonicalJson,validateProject,validateBoundedRegexPattern} from "./validate.js";
import {compilePair} from "./compiler.js";
import type {ParserProject,PairExport,ValidationIssue,ValidationResult,FieldType,LogIndex} from "./types.js";

export type RecipeBody="json"|"kv"|"csv"|"cef"|"leef"|"mixed"|"java_stacktrace"|"regex"|"generic_structural";
export type RecipeSource=RecipeBody|"syslog_rfc3164"|"syslog_rfc5424";
type Group="top_fields"|"ns_fields"|"vendor_fields";
type MapStage={op:"map_field";source:string;target:string;data_type:FieldType;group:Group;source_path_kind?:"literal_root"|"nested"};
type CastStage={op:"cast_type";target:string;data_type:Exclude<FieldType,"string">;timezone?:"UTC"};
type SplitFieldStage={op:"split_field";source:string;delimiter:string;targets:string[]};
type MergeFieldsStage={op:"merge_fields";sources:string[];delimiter:string;target:string};
type EnrichmentStage=SplitFieldStage|MergeFieldsStage;
type ClassifyStage={op:"classify";defaultIndex:LogIndex;rules:Array<{
 field:string;operator:"equals";value:string;index:LogIndex}>};
export type RecipeStage=
 | {op:"split_event";boundary:"single-line"|"blank-line"}
 | {op:"unwrap_syslog";version:1|3164;mode:"strict_header"}
 | {op:"dispatch_family";families:("json"|"kv"|"cef"|"leef"|"rfc5424_cef"|"rfc5424_leef"|"rfc3164_kv"|"rfc5424_json"|"rfc5424_kv"|"rfc3164_cef"|"rfc3164_leef"|"csv")[];mode:"strict_prefix"}
 | {op:"parse_json"|"parse_kv"|"parse_cef"|"parse_leef"|"parse_java_stacktrace"}
 | {op:"parse_generic_structural";profile?:ParserProject["extraction"]["genericStructuralProfile"]}
 | {op:"parse_regex";pattern:string}
 | {op:"parse_csv";columns:string[];delimiter:","|";"|"\t"}
 | MapStage | CastStage | SplitFieldStage | MergeFieldsStage | ClassifyStage
 | {op:"fallback_unparsed";mode:"retain_unparsed"};
export interface ParserRecipeV02 {
 contract:"parser-studio.recipe.v0.2";
 schemaRevision:"0.2"; compilerMode:"REVIEW_ONLY";
 projectId:string;sourceFormat:RecipeSource;bodyFormat:RecipeBody;
 sample:{sha256:string;events:number};
 stages:RecipeStage[];nativeVerified:false;targetVerified:false;
}
export interface RecipePairRequest {recipe:ParserRecipeV02;legacyProject:ParserProject}
export interface RecipeReceipt {
 contract:"parser-studio.recipe-compiler.v0.2";
 compilerMode:"V01_EQUIVALENT_SUBSET";
 recipeSha256:string;legacyProjectSha256:string;sourceSha256:string;
 sampleEventCount:number;stageCount:number;
 sourceHashVerifiedAgainstEvents:false;nativeUserParserVerified:false;
 targetImportVerified:false;outputProfile:"host-customized-pair.v0.1";
}
export interface RecipePairExport extends PairExport {
 recipeReceipt:RecipeReceipt;
}
const ajv=new Ajv({strict:true,allErrors:true});
const schemaValidate=ajv.compile(recipeSchema);
const UNSAFE=new Set(["__proto__","constructor","prototype"]);
const TYPES=new Set<FieldType>(["string","integer","ip","port","boolean","date"]);
const GROUPS=[["top_fields","topFields"],["ns_fields","nsFields"],
 ["vendor_fields","vendorFields"]] as const;
const PARSERS=new Set(["parse_json","parse_kv","parse_csv","parse_cef","parse_leef","parse_java_stacktrace","parse_regex","parse_generic_structural"]);
const BODY=new Set<RecipeBody>(["json","kv","csv","cef","leef","mixed","java_stacktrace","regex","generic_structural"]);
const rootKeys=["legacyProject","recipe"];
const error=(code:string,path:string):ValidationIssue=>({
 code,path,message:"Reviewed recipe is unsupported or mismatched: "+code});
function fail(code:string,path="/recipe"):ValidationResult {
 return {ok:false,issues:[error(code,path)]};
}
function exact(value:unknown,keys:readonly string[]):boolean {
 return !!value&&typeof value==="object"&&!Array.isArray(value)&&
  Object.keys(value).length===keys.length&&
  Object.keys(value).every(k=>keys.includes(k));
}
function pathOK(v:string,source=false):boolean{
 if(source&&v==='@timestamp')return true;
 return v.length<=128&&v.length>=1&&
  /^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$/.test(v)&&
  v.split(".").every(part=>!UNSAFE.has(part));
}
function sourceBody(project:ParserProject):{source:RecipeSource;body:RecipeBody}|null {
 const source=project.extraction.format;
 const body=["syslog_rfc3164","syslog_rfc5424"].includes(source)?
  project.extraction.syslogBodyFormat:source;
 if(!body||!BODY.has(body as RecipeBody)||
   (["syslog_rfc3164","syslog_rfc5424"].includes(source)&&body==="csv"))return null;
 return {source,body:body as RecipeBody};
}
function legacyAllowed(project:ParserProject):boolean {
 const enrichmentOk=(project.enrichment??[]).every(rule=>
  rule.operator==="split_field"||rule.operator==="merge_fields");
 return enrichmentOk&&!project.extraction.forwarder&&
  !project.normalization.eventProfiles&&!project.unsupportedOpaqueBlocks?.length&&
  (project.receiver.tcpFraming==="line"||
    ((project.receiver.tcpFraming==="blank_line_json"||
      project.receiver.tcpFraming==="blank_line_java")&&
      project.receiver.protocols.length===1&&
      project.receiver.protocols[0]==="tcp"&&
      project.extraction.format===(project.receiver.tcpFraming==="blank_line_java"?
        "java_stacktrace":"json")))&&
  project.receiver.delimiter===undefined&&
  (project.extraction.maxDepth===undefined||project.extraction.maxDepth===8)&&
  project.classification.rules.length<=24&&
  project.classification.rules.every(r=>r.operator==="equals"&&
    typeof r.value==="string"&&r.value.length<=128&&
    !/[\x00-\x1f\x7f]/.test(r.value))&&sourceBody(project)!==null;
}
function expectedMappings(project:ParserProject):MapStage[]{
 const items:MapStage[]=[];
 for(const [group,section] of GROUPS){
  for(const [source,rule] of Object.entries(project.normalization[section])){
   if(!pathOK(source,true)||!pathOK(rule.normalized_name)||!TYPES.has(rule.data_type))
    throw new Error("UNSUPPORTED_MAPPING_PATH");
   items.push({op:"map_field",source,target:rule.normalized_name,
    data_type:rule.data_type,group,
    ...(rule.source_path_kind?{source_path_kind:rule.source_path_kind}:{})});
  }
 }
 if(items.length<1||items.length>60)throw new Error("UNSUPPORTED_MAPPING_COUNT");
 return items;
}
function expectedEnrichment(project:ParserProject):EnrichmentStage[]{
 return (project.enrichment??[]).map(rule=>{
  if(rule.operator==="split_field")return {op:"split_field",source:rule.source,
   delimiter:rule.delimiter,targets:[...rule.targets]};
  if(rule.operator==="merge_fields")return {op:"merge_fields",sources:[...rule.sources],
   delimiter:rule.delimiter,target:rule.target};
  throw new Error("UNSUPPORTED_ENRICHMENT");
 });
}
function expectedClassify(project:ParserProject):ClassifyStage{
 return {op:"classify",defaultIndex:project.classification.defaultIndex,
  rules:project.classification.rules.map(r=>({
   field:r.field,operator:"equals",value:r.value as string,index:r.index
  }))};
}
/** Strict no-loss v0.1 projection for reviewed subset; refuses unmodeled stages. */
export function recipeFromLegacyProject(
 project:ParserProject,sampleSha256:string,sampleEvents:number
):ParserRecipeV02{
 if(!validateProject(project).ok||!legacyAllowed(project)||
  !/^draft-[a-z][a-z0-9_]{2,47}$/.test(project.projectId)||
  !/^[a-f0-9]{64}$/.test(sampleSha256)||!Number.isInteger(sampleEvents)||
  sampleEvents<1||sampleEvents>500)
  throw new Error("UNSUPPORTED_RECIPE_PROJECTION");
 const fmt=sourceBody(project)!;
 const stages:RecipeStage[]=[{op:"split_event",
  boundary:["blank_line_json","blank_line_java"].includes(project.receiver.tcpFraming)?
    "blank-line":"single-line"}];
 if(fmt.source==="syslog_rfc5424"||fmt.source==="syslog_rfc3164")
  stages.push({op:"unwrap_syslog",
    version:fmt.source==="syslog_rfc3164"?3164:1,mode:"strict_header"});
 if(fmt.body==="mixed"){
  stages.push({op:"dispatch_family",
    families:[...(project.extraction.mixedFormats??[])],mode:"strict_prefix"});
 }else if(fmt.body==="csv"){
  stages.push({op:"parse_csv",columns:project.extraction.csvColumns??[],
   delimiter:project.extraction.csvDelimiter??","});
 }else if(fmt.body==="regex"){
  const pattern=project.extraction.pattern;
  if(validateBoundedRegexPattern(pattern)!==null)throw new Error("UNSUPPORTED_REGEX_PATTERN");
  stages.push({op:"parse_regex",pattern:pattern!});
 }else if(fmt.body==="generic_structural"){
  stages.push({op:"parse_generic_structural",
    ...(project.extraction.genericStructuralProfile?{profile:project.extraction.genericStructuralProfile}:{})});
 }else stages.push({op:("parse_"+fmt.body) as
  "parse_json"|"parse_kv"|"parse_cef"|"parse_leef"|"parse_java_stacktrace"});
 for(const stage of expectedMappings(project)){
  stages.push(stage);
  if(stage.data_type!=="string"){
   stages.push({op:"cast_type",target:stage.target,data_type:stage.data_type,
    ...(stage.data_type==="date"?{timezone:"UTC" as const}:{})});
  }
 }
 stages.push(...expectedEnrichment(project));
 stages.push(expectedClassify(project),{op:"fallback_unparsed",mode:"retain_unparsed"});
 const recipe:ParserRecipeV02={contract:"parser-studio.recipe.v0.2",
  schemaRevision:"0.2",compilerMode:"REVIEW_ONLY",projectId:project.projectId,
  sourceFormat:fmt.source,bodyFormat:fmt.body,
  sample:{sha256:sampleSha256,events:sampleEvents},
  stages,nativeVerified:false,targetVerified:false};
 if(!schemaValidate(recipe))throw new Error("UNSUPPORTED_RECIPE_SCHEMA");
 return recipe;
}
/** Rejects unsupported, forged or lossy operator changes; no raw-value echo. */
export function validateRecipePair(input:unknown):ValidationResult{
 try {
  const encoded=JSON.stringify(input);
  if(!encoded||Buffer.byteLength(encoded,"utf8")>256*1024)
   return fail("INPUT_TOO_LARGE","/");
  if(!exact(input,rootKeys))return fail("INPUT_SHAPE","/");
  const req=input as RecipePairRequest;
  if(!schemaValidate(req.recipe))return fail("RECIPE_SCHEMA");
  const projectResult=validateProject(req.legacyProject);
  if(!projectResult.ok)return fail("LEGACY_PROJECT_INVALID","/legacyProject");
  if(!legacyAllowed(req.legacyProject))
   return fail("UNSUPPORTED_LEGACY_SEMANTICS","/legacyProject");
  const project=req.legacyProject,recipe=req.recipe;
  if(recipe.projectId!==project.projectId)return fail("PROJECT_MISMATCH");
  const fmt=sourceBody(project);
  if(!fmt||recipe.sourceFormat!==fmt.source||recipe.bodyFormat!==fmt.body)
   return fail("FORMAT_MISMATCH");
  const stages=recipe.stages;
  let i=0;
  const split=stages[i];
  if(!exact(split,["op","boundary"])||
      split?.op!=="split_event"||
      split.boundary!==((["blank_line_json","blank_line_java"].includes(project.receiver.tcpFraming))?
        "blank-line":"single-line"))
   return fail("BOUNDARY_UNSUPPORTED");
  i++;
  if(fmt.source==="syslog_rfc5424"||fmt.source==="syslog_rfc3164"){
   const unwrap=stages[i++];
   if(!exact(unwrap,["op","version","mode"])||
     unwrap?.op!=="unwrap_syslog"||unwrap.version!==(fmt.source==="syslog_rfc3164"?3164:1)||
     unwrap.mode!=="strict_header")
    return fail("ENVELOPE_UNSUPPORTED");
  }
  const parsed=stages[i++];
  if(fmt.body==="mixed"){
   if(!parsed||parsed.op!=="dispatch_family"||
     !exact(parsed,["op","families","mode"])||
     parsed.mode!=="strict_prefix"||
     canonicalJson(parsed.families)!==canonicalJson(project.extraction.mixedFormats??[]))
     return fail("MIXED_DISPATCH_MISMATCH");
  }else if(fmt.body==="csv"){
   if(!parsed||parsed.op!=="parse_csv"||
      !exact(parsed,["op","columns","delimiter"])||
      canonicalJson(parsed.columns)!==canonicalJson(project.extraction.csvColumns??[])||
      parsed.delimiter!==(project.extraction.csvDelimiter??","))
     return fail("CSV_STAGE_MISMATCH");
  }else if(fmt.body==="regex"){
   if(!parsed||parsed.op!=="parse_regex"||!exact(parsed,["op","pattern"])||
      parsed.pattern!==project.extraction.pattern||
      validateBoundedRegexPattern(parsed.pattern)!==null)
     return fail("REGEX_STAGE_MISMATCH");
  }else if(fmt.body==="generic_structural"){
   const profile=project.extraction.genericStructuralProfile;
   if(!parsed||parsed.op!=="parse_generic_structural"||
     !exact(parsed,profile?["op","profile"]:["op"])||parsed.profile!==profile)
    return fail("GENERIC_PROFILE_STAGE_MISMATCH");
  }else if(!parsed||parsed.op!=="parse_"+fmt.body||
    !exact(parsed,["op"])||!PARSERS.has(parsed.op))
   return fail("BODY_STAGE_MISMATCH");
  const actual:MapStage[]=[];
  const targets=new Set<string>();
  while(stages[i]?.op==="map_field"){
   const m=stages[i++] as MapStage;
   if(!(exact(m,["op","source","target","data_type","group"])||
     (exact(m,["op","source","target","data_type","group","source_path_kind"])&&
      ["literal_root","nested"].includes(m.source_path_kind??"")))||
     !pathOK(m.source,true)||!pathOK(m.target)||targets.has(m.target))
    return fail("UNSAFE_OR_DUPLICATE_MAPPING");
   targets.add(m.target);
   actual.push(m);
   if(m.data_type!=="string"){
    const cast=stages[i++] as CastStage|undefined;
    if(!cast||cast.op!=="cast_type"||cast.target!==m.target||
      cast.data_type!==m.data_type||
      (m.data_type==="date"?(cast.timezone!=="UTC"||
        !exact(cast,["op","target","data_type","timezone"])):
        !exact(cast,["op","target","data_type"])))
     return fail("CAST_STAGE_MISMATCH");
   }
  }
  const expected=expectedMappings(project);
  const signatures=(items:MapStage[])=>items.map(x=>canonicalJson(x)).sort();
  if(canonicalJson(signatures(actual))!==canonicalJson(signatures(expected)))
   return fail("MAPPING_STAGE_MISMATCH");
  for(const enrichment of expectedEnrichment(project)){
   const stage=stages[i++];
   if(canonicalJson(stage)!==canonicalJson(enrichment))
    return fail("ENRICHMENT_STAGE_MISMATCH");
  }
  const classify=stages[i++];
  if(!classify||classify.op!=="classify"||
    canonicalJson(classify)!==canonicalJson(expectedClassify(project)))
   return fail("CLASSIFY_STAGE_MISMATCH");
  const fallback=stages[i];
  if(i!==stages.length-1||!exact(fallback,["op","mode"])||
    fallback?.op!=="fallback_unparsed"||fallback.mode!=="retain_unparsed")
   return fail("FALLBACK_STAGE_MISMATCH");
  return {ok:true,issues:[]};
 }catch{return fail("INVALID_RECIPE_INPUT","/");}
}
const sha=(value:string)=>createHash("sha256").update(value,"utf8").digest("hex");
export function compileRecipePair(input:unknown):RecipePairExport{
 const validated=validateRecipePair(input);
 if(!validated.ok)throw new Error("Invalid ParserRecipe: "+
  validated.issues.map(x=>x.code).join(","));
 const {recipe,legacyProject}=input as RecipePairRequest;
 // The exact vetted v0.1 compiler is the only code generator. v0.2 stages
 // are fully checked for semantic equality before this point.
 const output=compilePair(legacyProject);
 return {...output,recipeReceipt:{
  contract:"parser-studio.recipe-compiler.v0.2",
  compilerMode:"V01_EQUIVALENT_SUBSET",recipeSha256:sha(canonicalJson(recipe)),
  legacyProjectSha256:sha(canonicalJson(legacyProject)),
  sourceSha256:recipe.sample.sha256,sampleEventCount:recipe.sample.events,
  stageCount:recipe.stages.length,
  sourceHashVerifiedAgainstEvents:false,nativeUserParserVerified:false,
  targetImportVerified:false,outputProfile:"host-customized-pair.v0.1"
 }};
}
