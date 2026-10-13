/** Strict, user-triggered v0.2 compiler negotiation over same-origin localhost.
 * Never posts raw sample events, LLM text, credentials or executable Ruby.
 */
import type {ParserRecipeV2} from './parserRecipeV2';
import type {BackendParserProject} from './backendAdapter';
import type {GeneratedPair} from './backendClient';
import {verifyGeneratedPair} from './artifactPackageClient';

const BASE='/api/v1/parser-pairs/recipe/v0.2';
const HEX=/^[a-f0-9]{64}$/;
const FAMILIES=['json','kv','csv','cef','leef'];
export interface ReviewedRecipeInput {
 recipe:ParserRecipeV2;
 legacyProject:BackendParserProject;
}
export interface RecipeCompilerReceipt {
 contract:'parser-studio.recipe-compiler.v0.2';
 compilerMode:'V01_EQUIVALENT_SUBSET';
 recipeSha256:string;legacyProjectSha256:string;sourceSha256:string;
 sampleEventCount:number;stageCount:number;
 sourceHashVerifiedAgainstEvents:false;nativeUserParserVerified:false;
 targetImportVerified:false;outputProfile:'host-customized-pair.v0.1';
}
export interface ReviewedRecipeCompilation {
 pair:GeneratedPair;receipt:RecipeCompilerReceipt;
}
function canonicalJson(value:unknown):string{
 if(Array.isArray(value))return '['+value.map(canonicalJson).join(',')+']';
 if(value!==null&&typeof value==='object'){
  const record=value as Record<string,unknown>;
  return '{'+Object.keys(record).sort().map(key=>
   JSON.stringify(key)+':'+canonicalJson(record[key])).join(',')+'}';
 }
 return JSON.stringify(value);
}
async function hash(value:string):Promise<string>{
 if(!globalThis.crypto?.subtle)throw new Error('Secure SHA-256 unavailable');
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));
 return [...new Uint8Array(digest)].map(item=>item.toString(16).padStart(2,'0')).join('');
}
function fail():never{throw new Error('The reviewed v0.2 compiler contract was not verified.');}
export async function checkRecipeV02Compiler(
 requester:typeof fetch=fetch,
 requiredEnvelope?:'rfc3164_strict_no_year_or_zone',
 requireMixed=false,
 requireJsonBlankLineTcp=false,
 requiredMixedFamilies:readonly string[]=[],
 requireJavaBlankLineTcp=false,
):Promise<boolean>{
 const res=await requester(BASE+'/capabilities',{
  method:'GET',cache:'no-store',credentials:'same-origin',
  headers:{Accept:'application/json'},
 });
 if(res.status===404)return false; // older backend: preserve existing v0.1 flow
 if(res.status!==200)fail();
 let raw:unknown;
 try{raw=await res.json();}catch{fail();}
 if(!raw||typeof raw!=='object')fail();
 const cap=raw as Record<string,unknown>;
 const values=cap.supportedBodyParsers,ops=cap.supportedOperators;
 const envelopes=cap.supportedEnvelopeParsers;
 if(cap.contract!=='parser-studio.recipe.v0.2'||
  cap.schemaRevision!=='0.2'||cap.compilerMode!=='V01_EQUIVALENT_SUBSET'||
  cap.currentOutputProfile!=='host-customized-pair.v0.1'||
  !Array.isArray(cap.inputRequires)||
  JSON.stringify(cap.inputRequires)!==JSON.stringify(['recipe','legacyProject'])||
  !Array.isArray(values)||!FAMILIES.every(f=>values.includes(f))||
  !Array.isArray(ops)||!['split_event','map_field','cast_type','fallback_unparsed']
    .every(s=>ops.includes(s))||
  (requiredEnvelope!==undefined&&(
    !Array.isArray(envelopes)||!envelopes.includes(requiredEnvelope)))||
  (requireMixed&&(
    !values.includes('mixed')||!ops.includes('dispatch_family')||
    !Array.isArray(cap.strictMixedSingleLineFamilies)||
    ![4,6,7,9,11,12].includes(cap.strictMixedSingleLineFamilies.length)||
    new Set(cap.strictMixedSingleLineFamilies).size!==cap.strictMixedSingleLineFamilies.length||
    !['json','kv','cef','leef'].every(f=>
      (cap.strictMixedSingleLineFamilies as unknown[]).includes(f))||
    (cap.strictMixedSingleLineFamilies.length>=6&&
      !['rfc5424_cef','rfc5424_leef'].every(f=>
        (cap.strictMixedSingleLineFamilies as unknown[]).includes(f)))||
    (cap.strictMixedSingleLineFamilies.length>=7&&
      !(cap.strictMixedSingleLineFamilies as unknown[]).includes('rfc3164_kv'))||
    (cap.strictMixedSingleLineFamilies.length>=9&&
      !['rfc5424_json','rfc5424_kv'].every(f=>
        (cap.strictMixedSingleLineFamilies as unknown[]).includes(f)))||
    (cap.strictMixedSingleLineFamilies.length>=11&&
      !['rfc3164_cef','rfc3164_leef'].every(f=>
        (cap.strictMixedSingleLineFamilies as unknown[]).includes(f)))||
    (cap.strictMixedSingleLineFamilies.length===12&&
      !(cap.strictMixedSingleLineFamilies as unknown[]).includes('csv'))||
    !requiredMixedFamilies.every(f=>
      (cap.strictMixedSingleLineFamilies as unknown[]).includes(f))
  ))||
  (requireJsonBlankLineTcp&&(
    cap.jsonBlankLineTcpFraming!==true||
    cap.jsonBlankLineOtherTransports!==false||
    cap.jsonBlankLineDelimiter!=='LF_LF'))||
  (requireJavaBlankLineTcp&&(
    !values.includes('java_stacktrace')||
    !ops.includes('parse_java_stacktrace')||
    cap.javaBlankLineTcpFraming!==true||
    cap.javaBlankLineOtherTransports!==false||
    cap.javaBlankLineDelimiter!=='LF_LF'||
    cap.javaStackTraceGrammar!=='EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1'))||
  cap.nativeUserParserVerified!==false||cap.targetImportVerified!==false||
  cap.sourceHashVerifiedAgainstEvents!==false||cap.apiDoesNotDeploy!==true)
  fail();
 return true;
}
async function post(operation:'validate'|'generate',input:ReviewedRecipeInput,
 requester:typeof fetch):Promise<unknown>{
 const json=JSON.stringify(input);
 if(new TextEncoder().encode(json).byteLength>256*1024)
  throw new Error('Review project exceeds the 256 KiB limit');
 const res=await requester(BASE+'/'+operation,{
  method:'POST',cache:'no-store',credentials:'same-origin',
  headers:{'Content-Type':'application/json',Accept:'application/json'},
  body:json,
 });
 if(res.status!==200)throw new Error('Reviewed v0.2 compiler unavailable or unsupported ('+res.status+').');
 try{return await res.json();}catch{fail();}
}
export async function compileReviewedRecipeV02(
 input:ReviewedRecipeInput,
 baseline:GeneratedPair|undefined,
 requester:typeof fetch=fetch,
):Promise<ReviewedRecipeCompilation>{
 if(!await checkRecipeV02Compiler(requester,
   input.recipe.sourceFormat==='syslog_rfc3164'? 'rfc3164_strict_no_year_or_zone':undefined,
   input.recipe.sourceFormat==='mixed',
   input.recipe.sourceFormat==='json'&&
     input.recipe.stages[0]?.op==='split_event'&&input.recipe.stages[0].boundary==='blank-line',
   input.recipe.stages.find(s=>s.op==='dispatch_family')?.op==='dispatch_family'
     ?(input.recipe.stages.find(s=>s.op==='dispatch_family') as
       Extract<typeof input.recipe.stages[number],{op:'dispatch_family'}>).families:[],
   input.recipe.sourceFormat==='java_stacktrace')) {
  throw new Error('The current backend does not advertise v0.2 compilation.');
 }
 const validation=await post('validate',input,requester);
 if(!validation||typeof validation!=='object')fail();
 const verdict=validation as Record<string,unknown>;
 if(verdict.ok!==true||!Array.isArray(verdict.issues)||verdict.issues.length!==0||
    verdict.compilerMode!=='V01_EQUIVALENT_SUBSET'||
    verdict.nativeUserParserVerified!==false||verdict.targetImportVerified!==false)fail();
 const generated=await post('generate',input,requester);
 if(!generated||typeof generated!=='object')fail();
 const output=generated as {recipeReceipt?:Partial<RecipeCompilerReceipt>}&GeneratedPair;
 const receipt=output.recipeReceipt;
 if(!receipt||receipt.contract!=='parser-studio.recipe-compiler.v0.2'||
   receipt.compilerMode!=='V01_EQUIVALENT_SUBSET'||
   receipt.outputProfile!=='host-customized-pair.v0.1'||
   receipt.sourceHashVerifiedAgainstEvents!==false||
   receipt.nativeUserParserVerified!==false||receipt.targetImportVerified!==false||
   !receipt.recipeSha256||!HEX.test(receipt.recipeSha256)||
   !receipt.legacyProjectSha256||!HEX.test(receipt.legacyProjectSha256)||
   receipt.sourceSha256!==input.recipe.sample.sha256||
   receipt.sampleEventCount!==input.recipe.sample.events||
   receipt.stageCount!==input.recipe.stages.length||
   receipt.recipeSha256!==await hash(canonicalJson(input.recipe))||
   receipt.legacyProjectSha256!==await hash(canonicalJson(input.legacyProject)))fail();
 await verifyGeneratedPair(output);
 if(output.manifest.projectId!==input.legacyProject.projectId||
   output.manifest.projectRevision!==input.legacyProject.revision)fail();
 if(baseline && (canonicalJson(output.files)!==canonicalJson(baseline.files)||
  canonicalJson(output.manifest)!==canonicalJson(baseline.manifest))) {
  throw new Error('The v0.2 staged compiler differs from the validated v0.1 pair.');
 }
 return {pair:output,receipt:receipt as RecipeCompilerReceipt};
}
