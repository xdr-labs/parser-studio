import {createServer,type IncomingMessage,type Server,type ServerResponse} from "node:http";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {TextDecoder} from "node:util";
import {BACKEND_CAPABILITIES} from "./capabilities.js";
import {compilePair} from "./compiler.js";
import {validateProject,MAX_PROJECT_BYTES} from "./validate.js";
import {inspectPair,MAX_IMPORT_BYTES,PairInspectionError} from "./import.js";
import {buildArtifactPackage,ArtifactPackageError} from "./artifact-package.js";
import {compileRecipePair,validateRecipePair} from "./parser-recipe-v02.js";
import {hasValidUnicodeJson} from "./unicode.js";
import projectSchema from "../schema/parser-project.v0.1.schema.json" with {type:"json"};
import recipeSchema from "../schema/parser-recipe.v0.2.schema.json" with {type:"json"};
import type {PairExport} from "./types.js";

/**
 * Shipping HTTP entrypoint: intentionally imports ONLY offline parser
 * validation/compilation/inspection/packaging. Historical http.ts contains
 * optional target, sensor, Interflow and Test Lab integrations; it is not
 * imported, constructed or reachable from this production-shaped source.
 *
 * The old shared HTTP source remains in Git for historical regression tests.
 * No app/server-originated target operations or automatic AI upload exist.
 */
const ALLOWED:Readonly<Record<string,readonly string[]>>=Object.freeze({
  "/health":["GET"],
  "/api/v1/parser-pairs/schema":["GET"],
  "/api/v1/parser-pairs/capabilities":["GET"],
  "/api/v1/parser-pairs/validate":["POST"],
  "/api/v1/parser-pairs/generate":["POST"],
  "/api/v1/parser-pairs/inspect":["POST"],
  "/api/v1/parser-pairs/package":["POST"],
  "/api/v1/parser-pairs/recipe/v0.2/schema":["GET"],
  "/api/v1/parser-pairs/recipe/v0.2/capabilities":["GET"],
  "/api/v1/parser-pairs/recipe/v0.2/validate":["POST"],
  "/api/v1/parser-pairs/recipe/v0.2/generate":["POST"],
});
const JSON_CONTENT_TYPE=/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i;

export const MAINLINE_AUTHORING_CAPABILITIES=Object.freeze({
  contract:BACKEND_CAPABILITIES.contract,
  projectSchemaRevision:BACKEND_CAPABILITIES.projectSchemaRevision,
  authoring:{
    ...BACKEND_CAPABILITIES.authoring,
    syntheticStarterTemplatesAvailable:false,
    syntheticTemplateHttpAvailable:false,
    deterministicNameOnlyMappingHttpAvailable:false,
  },
  downloads:{
    individualGeneratedFiles:true,
    zipWithManifest:true,
    requiresDpConnection:false,
    requiresApiKey:false,
    autoDeploys:false,
    exactArtifactRevision:true,
  },
  import:{
    exactInternalPairsEditable:true,
    unknownLegacyRubyEditable:false,
    structuralInspectionOnly:true,
  },
  verification:{
    engineVerified:false,
    targetImportVerified:false,
    liveListenerVerified:false,
    proprietaryLoaderVerified:false,
  },
  limits:BACKEND_CAPABILITIES.limits,
});

/** Compatibility data for the bounded manual ChatGPT Recipe v0.2 route. */
const RECIPE_AUTHORING_CAPABILITIES=Object.freeze({
  contract:"parser-studio.recipe.v0.2",schemaRevision:"0.2",
  compilerMode:"V01_EQUIVALENT_SUBSET",currentOutputProfile:"host-customized-pair.v0.1",
  inputRequires:["recipe","legacyProject"],
  supportedBodyParsers:["json","kv","csv","cef","leef","mixed","java_stacktrace","regex"],
  jsonBlankLineTcpFraming:true,jsonBlankLineOtherTransports:false,
  jsonBlankLineDelimiter:"LF_LF",
  javaBlankLineTcpFraming:true,javaBlankLineOtherTransports:false,
  javaBlankLineDelimiter:"LF_LF",
  javaStackTraceGrammar:"EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1",
  strictMixedSingleLineFamilies:["json","kv","cef","leef",
    "rfc5424_cef","rfc5424_leef","rfc3164_kv","rfc5424_json","rfc5424_kv",
    "rfc3164_cef","rfc3164_leef","csv"],
  supportedEnvelopeParsers:["none","rfc3164_strict_no_year_or_zone","rfc5424_v1_strict"],
  supportedOperators:["split_event","unwrap_syslog","dispatch_family",
    "parse_json","parse_kv","parse_csv","parse_cef","parse_leef","parse_java_stacktrace",
    "parse_regex","map_field","cast_type","split_field","merge_fields",
    "classify_equals","fallback_unparsed"],
  boundedRegexNamedCaptureSubset:true,boundedRegexMaxPatternChars:256,
  boundedRegexRuntimeTimeoutMs:50,
  unsupported:["rfc3164_timestamp_inference","mixed_rfc3164_unreviewed_bodies",
    "mixed_other_syslog_envelopes","mixed_csv_unreviewed_schema",
    "multiline_unframed_generic","unbounded_or_unsafe_regex","ruby_execution",
    "jsonata","classification_exists","enrichment_unmodeled"],
  sourceHashVerifiedAgainstEvents:false,nativeUserParserVerified:false,
  nativeProjectVerificationConfigured:false,nativeProjectVerificationRequiresAuth:true,
  targetImportVerified:false,apiDoesNotDeploy:true,
});

export function isMainlineAuthoringRoute(path:string,method:string):boolean{
  // Inherited JS object property names (constructor, toString, __proto__)
  // are not HTTP routes and must never be considered method arrays.
  return Object.hasOwn(ALLOWED,path)&&ALLOWED[path]?.includes(method)===true;
}

function send(response:ServerResponse,status:number,body:unknown):void{
  response.writeHead(status,{
    "content-type":"application/json; charset=utf-8",
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    "referrer-policy":"no-referrer",
    "x-frame-options":"DENY",
    "cross-origin-resource-policy":"same-origin",
  });
  response.end(JSON.stringify(body));
}

async function strictJsonInput(req:IncomingMessage,maximum:number):Promise<unknown>{
  const chunks:Buffer[]=[];
  let received=0;
  for await (const chunk of req){
    const data=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk as Uint8Array);
    received+=data.length;
    if(received>maximum)
      throw Object.assign(Error("Oversized request"),{code:"LIMIT"});
    chunks.push(data);
  }
  try{
    const raw=new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks));
    const data=JSON.parse(raw) as unknown;
    if(!hasValidUnicodeJson(data))throw Error("Invalid Unicode");
    return data;
  }catch{
    throw Object.assign(Error("Invalid JSON"),{code:"JSON"});
  }
}

function requestError(error:unknown,response:ServerResponse,defaultCode:string):void{
  const code=(error as {code?:string})?.code;
  if(code==="LIMIT")send(response,413,{error:"INPUT_TOO_LARGE"});
  else if(code==="JSON")send(response,400,{error:"INVALID_JSON"});
  else send(response,500,{error:defaultCode});
}

function sendPackage(response:ServerResponse,content:{
  zip:Buffer;filename:string;zipSha256:string;
  manifest:{artifactRevisionId:string;selectedParserPort:number};
}):void{
  response.writeHead(200,{
    "content-type":"application/zip",
    "content-disposition":'attachment; filename="'+content.filename+'"',
    "content-length":content.zip.length,
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    "referrer-policy":"no-referrer",
    "x-frame-options":"DENY",
    "cross-origin-resource-policy":"same-origin",
    "x-parser-artifact-revision":content.manifest.artifactRevisionId,
    "x-parser-zip-sha256":content.zipSha256,
    "x-parser-listener-port":String(content.manifest.selectedParserPort),
  });
  response.end(content.zip);
}

async function handleOfflineRequest(req:IncomingMessage,res:ServerResponse):Promise<void>{
  const path=(req.url??"").split("?")[0]??"";
  if(!isMainlineAuthoringRoute(path,req.method??"")){
    send(res,404,{error:"AUTHORING_ONLY_ROUTE_NOT_AVAILABLE"});return;
  }
  if(path==="/health"){
    send(res,200,{status:"ok",service:"parser-pair-backend",version:"0.1"});return;
  }
  if(path==="/api/v1/parser-pairs/schema"){send(res,200,projectSchema);return;}
  if(path==="/api/v1/parser-pairs/capabilities"){
    send(res,200,MAINLINE_AUTHORING_CAPABILITIES);return;
  }
  if(path==="/api/v1/parser-pairs/recipe/v0.2/schema"){
    send(res,200,recipeSchema);return;
  }
  if(path==="/api/v1/parser-pairs/recipe/v0.2/capabilities"){
    send(res,200,RECIPE_AUTHORING_CAPABILITIES);return;
  }
  const packageRoute=path==="/api/v1/parser-pairs/package";
  const recipeRoute=path.startsWith("/api/v1/parser-pairs/recipe/v0.2/");
  const inspectRoute=path==="/api/v1/parser-pairs/inspect";
  const maxBytes=packageRoute||inspectRoute?MAX_IMPORT_BYTES:MAX_PROJECT_BYTES;
  if(!JSON_CONTENT_TYPE.test(req.headers["content-type"]??"")){
    send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
  }
  const declared=Number(req.headers["content-length"]??0);
  if(Number.isFinite(declared)&&declared>maxBytes){
    send(res,413,{error:"INPUT_TOO_LARGE"});return;
  }
  let input:unknown;
  try{input=await strictJsonInput(req,maxBytes);}
  catch(error){
    requestError(error,res,recipeRoute?"RECIPE_GENERATION_FAILED":
      packageRoute?"ARTIFACT_PACKAGE_FAILED":"GENERATION_ERROR");
    return;
  }
  if(recipeRoute){
    try{
      const result=validateRecipePair(input);
      if(!result.ok){
        send(res,422,{error:"UNSUPPORTED_RECIPE_V02",issues:result.issues});return;
      }
      if(path.endsWith("/validate")){
        send(res,200,{ok:true,issues:[],compilerMode:"V01_EQUIVALENT_SUBSET",
          nativeUserParserVerified:false,targetImportVerified:false});return;
      }
      send(res,200,compileRecipePair(input));
    }catch(error){requestError(error,res,"RECIPE_GENERATION_FAILED");}
    return;
  }
  if(packageRoute){
    try{
      if(!input||typeof input!=="object"||Array.isArray(input)||
         Object.keys(input).sort().join(",")!=="pair,version"){
        send(res,422,{error:"ARTIFACT_REQUEST_INVALID"});return;
      }
      const request=input as Record<string,unknown>;
      const result=buildArtifactPackage(request.pair as PairExport,request.version as string);
      sendPackage(res,result);
    }catch(error){
      if(error instanceof ArtifactPackageError)send(res,422,{error:error.code});
      else requestError(error,res,"ARTIFACT_PACKAGE_FAILED");
    }
    return;
  }
  if(inspectRoute){
    try{send(res,200,inspectPair(input as {name:string;confContent:string;fragmentContent:string}));}
    catch(error){
      if(error instanceof PairInspectionError){
        const location=error.code==="PAIR_NAME_INVALID"?"/name":
          error.code==="PAIR_CONTENT_INVALID"?"/files":"/";
        send(res,422,{error:"INVALID_PAIR",issues:[{
          code:error.code,path:location,message:error.message,
        }]});
      }else send(res,500,{error:"INSPECTION_ERROR"});
    }
    return;
  }
  try{
    const validated=validateProject(input);
    if(path==="/api/v1/parser-pairs/validate"){
      send(res,validated.ok?200:422,validated);return;
    }
    if(!validated.ok){
      send(res,422,{error:"INVALID_PROJECT",issues:validated.issues});return;
    }
    send(res,200,compilePair(input));
  }catch(error){requestError(error,res,"GENERATION_ERROR");}
}

export function createMainlineAuthoringServer():Server{
  return createServer((request,response)=>{
    void handleOfflineRequest(request,response).catch(()=>{
      if(response.headersSent){response.destroy();return;}
      send(response,500,{error:"OFFLINE_AUTHORING_FAILED"});
    });
  });
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const port=Number(process.env["PARSER_BACKEND_PORT"]??"4179");
  if(!Number.isSafeInteger(port)||port<1024||port>65535)
    throw Error("PARSER_BACKEND_PORT must be an unprivileged TCP port");
  createMainlineAuthoringServer().listen(port,"127.0.0.1",()=>{
    process.stdout.write("Parser Studio offline authoring backend listening on 127.0.0.1:"+port+"\n");
  });
}
