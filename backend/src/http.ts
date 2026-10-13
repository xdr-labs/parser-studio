import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { TextDecoder } from "node:util";
import { hasValidUnicodeJson } from "./unicode.js";
import { compilePair } from "./compiler.js";
import {compileRecipePair,validateRecipePair} from "./parser-recipe-v02.js";
import {mineDrain3,Drain3WorkerError} from "./drain3-worker.js";
import {AIReviewGateway,AIReviewGatewayError} from "./ai-review-gateway.js";
import recipeSchema from "../schema/parser-recipe.v0.2.schema.json" with {type:"json"};
import { BACKEND_CAPABILITIES } from "./capabilities.js";
import {listParserTemplates,instantiateParserTemplate,ParserTemplateError} from "./parser-templates.js";
import {buildImportLossReport} from "./import-loss-report.js";
import {suggestFieldMappings,MappingSuggestionError} from "./mapping-suggestions.js";
import {TargetApplyMockGateway} from "./target-apply-bff.js";
import {TargetDeploymentError} from "./target-deployment.js";
import {ArtifactRevisionHistory,ArtifactRevisionHistoryError,
  type RevisionOwner} from "./artifact-revision-history.js";
import {verifySyntheticNativeCapabilityManifest}
  from "./native-capability-manifest.js";
import {buildArtifactPackage,ArtifactPackageError} from "./artifact-package.js";
import {proposeParserPort,PortPlanError} from "./stellar-port-plan.js";
import {createSyntheticPreview,SyntheticPreviewError} from "./testlab-synthetic.js";
import {SyntheticSessionController,TestLabSessionError} from "./testlab-session.js";
import {TestLabEvidenceError} from "./testlab-evidence.js";
import {exportRedactedEvidenceReport,TestLabReportExportError} from "./testlab-report-export.js";
import {summarizeRedactedEvidenceReport} from "./testlab-evidence-summary.js";
import {buildInterflowQuery,compareInterflowHits,
  InterflowContractError} from "./stellar-interflow.js";
import {pollBoundedInterflow,InterflowPollError} from "./stellar-interflow-poll.js";
import {ScenarioContractError,selectScenarioPreview,
  type ReplayScenario} from "./testlab-scenario.js";
import {LegacyPocClient,LegacyApiError} from "./stellar-legacy-client.js";
import {LEGACY_POC_CAPABILITIES,LegacyContractError,
  makeLegacyUploadPlan,requireDisposablePocWrite} from "./stellar-legacy-plan.js";
import type {PairExport} from "./types.js";

import { inspectPair, MAX_IMPORT_BYTES, PairInspectionError } from "./import.js";
import projectSchema from "../schema/parser-project.v0.1.schema.json" with { type: "json" };
import { MAX_PROJECT_BYTES, validateProject } from "./validate.js";

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "cross-origin-resource-policy": "same-origin",
  });
  res.end(JSON.stringify(body));
}

async function jsonInput(req: IncomingMessage, maxBytes = MAX_PROJECT_BYTES): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += bytes.length;
    if (size > maxBytes) {
      throw Object.assign(new Error("Request body exceeds configured size limit"), { code: "LIMIT" });
    }
    chunks.push(bytes);
  }
  try {
    // Buffer.toString silently substitutes malformed UTF-8 bytes. Imported
    // Ruby/CONF and normalization drafts must not be altered on ingestion.
    const source=new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks));
    const input=JSON.parse(source) as unknown;
    if(!hasValidUnicodeJson(input))throw new Error("Invalid Unicode escape");
    return input;
  }
  catch { throw Object.assign(new Error("Invalid JSON request"), {code: "JSON"}); }
}

/**
 * Optional server-only injection. By default there is NO credential/client,
 * read authorization or write capability, regardless of caller body.
 */
export interface BackendServerOptions {
  /** Explicit offline mock-only target Apply injection. Default disabled. */
  targetApplyMockGateway?:TargetApplyMockGateway;
  /** Owner-only, in-memory offline artifact history; disabled by default. */
  artifactRevisionHistory?:ArtifactRevisionHistory;
  authorizeArtifactRevision?:(request:IncomingMessage)=>Promise<RevisionOwner|null>;
  /** Optional PRIVATE offline qualification evidence, never user/target proof. */
  nativeCapabilityAccess?:{
    manifest:unknown;
    expectedHead:string;
    authorize:(request:IncomingMessage)=>Promise<boolean>;
  };
  /** Opt-in private offline miner; no external AI, no default network egress.
   * Both trusted interpreter path and authorization are server-owned.
   * This feature is disabled and must not accept raw input by default. */
  drain3Worker?:{
    pythonExecutable:string;
    authorize:(request:IncomingMessage)=>Promise<boolean>;
  };
  /** Disabled by default: externally configured provider, durable token ledger,
   * independent identity authorization and pre-egress audit are mandatory. */
  aiReviewGateway?:AIReviewGateway;
  legacyClient?:LegacyPocClient;
  authorizeLegacyRead?:(request:IncomingMessage)=>Promise<boolean>;
  legacyTestWritesEnabled?:boolean;
  /** Injected trusted backend/in-network inventory; never from browser JSON. */
  /** Required for raw event preview; unconfigured preview is denied. */
  authorizeTestLabPreview?:(request:IncomingMessage)=>Promise<boolean>;
  /** Deterministic synthetic tests inject a clock; never client-supplied. */
  syntheticClock?:()=>number;
  /** Server-controlled in-network delivery agent and session permissions.
   *  Defaults to UNCONFIGURED; never accepts target/sink from caller JSON. */
  testLabController?:SyntheticSessionController;
  /** Authenticate the current user and return their stable server-side actor ID.
   * Never use an unverified browser-provided actor ID. Null denies access. */
  authorizeTestLabSession?:(request:IncomingMessage,runId?:string)=>Promise<string|null>;
  /** Independent tenant-scoped Interflow data-read permission for run owner. */
  authorizeInterflowRead?:(request:IncomingMessage,runId:string)=>Promise<string|null>;
  /** Private audit records schema, tenant, time and field names only. */
  auditInterflowRead?:(event:{tenant:string;runId:string;index:string;
    startMs:number;endMs:number;fieldNames:string[]})=>Promise<void>;
  portPlanningContext?:{
    sensorParserPorts:readonly number[];
    localReservedPorts:readonly number[];
    adminReservedPorts:readonly number[];
    sensorBindingsComplete:boolean;
    reservationsComplete:boolean;
    rangeStart?:number;
    rangeEnd?:number;
  };
}

function mappedLegacyError(res:ServerResponse,error:unknown):void{
  if(error instanceof LegacyApiError){
    send(res,502,{error:"LEGACY_UPSTREAM_HTTP",operation:error.method,
      upstreamStatus:error.httpStatus,runtimeParsingVerified:false});
  }else if(error instanceof PortPlanError){
    send(res,422,{error:error.code,deployableNow:false});
  }else if(error instanceof LegacyContractError){
    const code=error.code;
    const status=/CONFLICT|UNVERIFIED/.test(code)?409:
      /DISABLED|DENIED|CONFIRMATION|APPROVAL|AUDIT/.test(code)?403:422;
    send(res,status,{error:code,runtimeParsingVerified:false});
  }else{
    // Do not propagate request bytes, vendor bodies, credentials or stack.
    send(res,502,{error:"LEGACY_REQUEST_FAILED",runtimeParsingVerified:false});
  }
}

/**
 * Private local integration endpoint. No network listener is opened until
 * a caller invokes server.listen. When run from the CLI, binds loopback only.
 */
export function createBackendServer(options:BackendServerOptions={}): Server {
  const server=createServer(async (req, res) => {
    const path = req.url?.split("?")[0] || "";
    if (path === "/health" && req.method === "GET") {
      send(res, 200, {status:"ok", service:"parser-pair-backend", version:"0.1"});
      return;
    }
    if (path === "/api/v1/parser-pairs/schema" && req.method === "GET") {
      send(res, 200, projectSchema);
      return;
    }
    // All AI endpoints disabled by default; GET is data-free and auth-gated,
    // POST sends strict enumerated metadata only (never browser raw events).
    const aiBase="/api/v1/parser-pairs/ai/v0.1";
    if(path===aiBase+"/capabilities"||path===aiBase+"/review"){
      const isGet=path.endsWith("/capabilities");
      if(req.method!==(isGet?"GET":"POST")){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      const gateway=options.aiReviewGateway;
      if(!gateway){send(res,403,{error:"AI_REVIEW_DISABLED"});return;}
      const actor=await gateway.authorize(req);
      if(!actor){send(res,403,{error:"AI_REVIEW_DENIED"});return;}
      if(isGet){send(res,200,gateway.capabilities());return;}
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]??0)>3072){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const input=await jsonInput(req,3072);
        send(res,200,await gateway.run(input,actor));
      }catch(error){
        if((error as {code?:string})?.code==="LIMIT")
          send(res,413,{error:"INPUT_TOO_LARGE"});
        else if((error as {code?:string})?.code==="JSON")
          send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof AIReviewGatewayError){
          const code=error.code;
          const status=code==="AI_REVIEW_BUSY"||code==="AI_BUDGET_DENIED"?429:
            code==="AI_METADATA_UNSUPPORTED"||code==="AI_EXPLICIT_CONSENT_REQUIRED"||
            code==="AI_CANDIDATE_UNTRUSTED"?422:503;
          send(res,status,{error:code});
        }else send(res,503,{error:"AI_REVIEW_UNAVAILABLE"});
      }
      return;
    }
    // Public data-free capability probe is still owner-authorized.
    if(path==="/api/v1/parser-pairs/patterns/drain3/capabilities"){
      if(req.method!=="GET"){send(res,405,{error:"METHOD_NOT_ALLOWED"});return;}
      const provider=options.drain3Worker;
      if(!provider){send(res,403,{error:"DRAIN3_DISABLED"});return;}
      let authorized=false;
      try{authorized=await provider.authorize(req);}catch{authorized=false;}
      if(!authorized){send(res,403,{error:"DRAIN3_DENIED"});return;}
      send(res,200,{contract:"parser-studio.drain3-capabilities.v0.1",
        available:true,requiresExplicitConfirmation:true,
        engine:"Drain3 0.9.11",sameOriginRawSourceTransfer:true,
        noPersistence:true,maxTrainingEvents:500,maxHoldoutEvents:500,
        nativeParserVerified:false,targetImportVerified:false,
        noExternalLlmCalls:true});
      return;
    }
    // Explicit consent + independent backend authentication + trusted interpreter.
    // No raw samples enter this route without an authenticated enabled injector.
    if(path==="/api/v1/parser-pairs/patterns/drain3"){
      if(req.method!=="POST"){send(res,405,{error:"METHOD_NOT_ALLOWED"});return;}
      const provider=options.drain3Worker;
      if(!provider){send(res,403,{error:"DRAIN3_DISABLED"});return;}
      let authorized=false;
      try{authorized=await provider.authorize(req);}
      catch{authorized=false;}
      if(!authorized){send(res,403,{error:"DRAIN3_DENIED"});return;}
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|\\"utf-8\\"))?$/i.test(
        req.headers["content-type"]??"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]??0)>65536){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const body=await jsonInput(req,65536);
        if(!body||typeof body!=="object"||Array.isArray(body)||
           Object.keys(body).sort().join(",")!=="confirmed,contract,holdout,training"||
           (body as Record<string,unknown>).confirmed!==true){
          send(res,422,{error:"DRAIN3_EXPLICIT_CONFIRMATION_REQUIRED"});return;
        }
        const raw=body as Record<string,unknown>;
        const report=await mineDrain3({
          contract:raw.contract,training:raw.training,holdout:raw.holdout
        },provider.pythonExecutable);
        send(res,200,report);
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT"||code==="INPUT_TOO_LARGE")
          send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof Drain3WorkerError){
          const bad=error.code==="DRAIN3_INPUT_UNSUPPORTED"||
            error.code==="DRAIN3_OUTPUT_UNTRUSTED";
          send(res,bad?422:503,{error:error.code});
        }else send(res,503,{error:"DRAIN3_WORKER_UNAVAILABLE"});
      }
      return;
    }
    // Separate strict staged v0.2 endpoint: v0.1 API contract is unchanged.
    // Only a completely matching, reviewed legacy v0.1 projection compiles.
    const recipeBase="/api/v1/parser-pairs/recipe/v0.2";
    if(path===recipeBase+"/schema"||path===recipeBase+"/capabilities"||
       path===recipeBase+"/validate"||path===recipeBase+"/generate"){
      const isGet=path.endsWith("/schema")||path.endsWith("/capabilities");
      if(req.method!==(isGet?"GET":"POST")){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      if(path.endsWith("/schema")){send(res,200,recipeSchema);return;}
      if(path.endsWith("/capabilities")){
        send(res,200,{
          contract:"parser-studio.recipe.v0.2",schemaRevision:"0.2",
          compilerMode:"V01_EQUIVALENT_SUBSET",currentOutputProfile:"host-customized-pair.v0.1",
          inputRequires:["recipe","legacyProject"],
          supportedBodyParsers:["json","kv","csv","cef","leef","mixed"],
          jsonBlankLineTcpFraming:true,
          jsonBlankLineOtherTransports:false,
          jsonBlankLineDelimiter:"LF_LF",
          strictMixedSingleLineFamilies:["json","kv","cef","leef","rfc5424_cef","rfc5424_leef","rfc3164_kv","rfc5424_json","rfc5424_kv"],
          supportedEnvelopeParsers:["none","rfc3164_strict_no_year_or_zone","rfc5424_v1_strict"],
          supportedOperators:["split_event","unwrap_syslog","dispatch_family","parse_json","parse_kv",
            "parse_csv","parse_cef","parse_leef","map_field","cast_type",
            "classify_equals","fallback_unparsed"],
          unsupported:["rfc3164_timestamp_inference","mixed_rfc3164_non_kv","mixed_other_syslog_envelopes",
            "mixed_csv","multiline","arbitrary_regex",
            "ruby_execution","jsonata","classification_exists","enrichment_unmodeled"],
          sourceHashVerifiedAgainstEvents:false,nativeUserParserVerified:false,
          targetImportVerified:false,apiDoesNotDeploy:true,
        });return;
      }
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]??0)>MAX_PROJECT_BYTES){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const input=await jsonInput(req,MAX_PROJECT_BYTES);
        const result=validateRecipePair(input);
        if(!result.ok){
          send(res,422,{error:"UNSUPPORTED_RECIPE_V02",issues:result.issues});return;
        }
        if(path.endsWith("/validate")){
          send(res,200,{ok:true,issues:[],compilerMode:"V01_EQUIVALENT_SUBSET",
            nativeUserParserVerified:false,targetImportVerified:false});return;
        }
        send(res,200,compileRecipePair(input));
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else send(res,500,{error:"RECIPE_GENERATION_FAILED"});
      }
      return;
    }
    if (path === "/api/v1/parser-pairs/capabilities") {
      if (req.method !== "GET") {
        send(res, 405, {error: "METHOD_NOT_ALLOWED"});
      } else {
        send(res, 200, {...BACKEND_CAPABILITIES,downloads:{
          ...BACKEND_CAPABILITIES.downloads,
          revisionHistoryDurableAcrossRestart:options.artifactRevisionHistory?.persistent===true,
        }});
      }
      return;
    }
    // Explicitly injected, authenticated, PUBLIC-SYNTHETIC native evidence.
    // Default server does not load local qualification files or expose this.
    if(path==="/api/v1/parser-pairs/native-capability-manifest"){
      if(req.method!=="GET"){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      if(req.url?.includes("?")){
        send(res,422,{error:"NATIVE_CAPABILITY_QUERY_INVALID"});return;
      }
      const access=options.nativeCapabilityAccess;
      if(!access||typeof access.authorize!=="function"){
        send(res,403,{error:"NATIVE_CAPABILITY_DISABLED"});return;
      }
      let allowed=false;
      try{allowed=await access.authorize(req)===true;}
      catch{/* Private auth errors are never returned. */}
      if(!allowed){
        send(res,403,{error:"NATIVE_CAPABILITY_ACCESS_DENIED"});return;
      }
      try{
        const manifest=verifySyntheticNativeCapabilityManifest(
          access.manifest,access.expectedHead);
        send(res,200,manifest);
      }catch{
        send(res,503,{error:"NATIVE_CAPABILITY_EVIDENCE_UNAVAILABLE",
          targetImportVerified:false});
      }
      return;
    }
    // Pure, read-only diagnostics: no Ruby execution, raw-log output or DP IO.
    const importLoss=path==="/api/v1/parser-pairs/import-loss-report";
    const mappingHints=path==="/api/v1/parser-pairs/mapping-suggestions";
    if(importLoss||mappingHints){
      if(req.method!=="POST"){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      const limit=importLoss?MAX_IMPORT_BYTES:MAX_PROJECT_BYTES;
      if(Number(req.headers["content-length"]??0)>limit){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const input=await jsonInput(req,limit);
        if(importLoss){
          if(!input||typeof input!=="object"||Array.isArray(input)||
             Object.keys(input).sort().join(",")!==
             "confContent,fragmentContent,name"){
            send(res,422,{error:"IMPORT_LOSS_INPUT_INVALID"});return;
          }
          send(res,200,buildImportLossReport(input as
            Parameters<typeof buildImportLossReport>[0]));
        }else send(res,200,suggestFieldMappings(input as
          Parameters<typeof suggestFieldMappings>[0]));
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof PairInspectionError)
          send(res,422,{error:error.code});
        else if(error instanceof MappingSuggestionError)
          send(res,422,{error:error.code});
        else send(res,500,{error:"ANALYSIS_FAILED"});
      }
      return;
    }
    // Public synthetic template catalog; instantiation is offline only.
    const templateBase="/api/v1/parser-pairs/templates";
    if(path===templateBase||path===templateBase+"/instantiate"){
      const instantiate=path===templateBase+"/instantiate";
      if(req.method!==(instantiate?"POST":"GET")){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      if(!instantiate){
        send(res,200,{contract:"parser-template-catalog.v0.1",
          offlineOnly:true,templates:listParserTemplates()});
        return;
      }
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]??0)>MAX_PROJECT_BYTES){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const raw=await jsonInput(req,MAX_PROJECT_BYTES);
        if(!raw||typeof raw!=="object"||Array.isArray(raw)||
          Object.keys(raw).sort().join(",")!=="options,templateId"||
          typeof (raw as Record<string,unknown>)["templateId"]!=="string"){
          send(res,422,{error:"TEMPLATE_REQUEST_INVALID"});return;
        }
        const input=raw as Record<string,unknown>;
        const project=instantiateParserTemplate(input["templateId"] as string,
          input["options"] as Parameters<typeof instantiateParserTemplate>[1]);
        send(res,200,{contract:"parser-template-draft.v0.1",
          project,targetImportVerified:false,deployableNow:false,autodeploy:false});
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof ParserTemplateError)
          send(res,error.code==="TEMPLATE_NOT_FOUND"?404:422,{error:error.code});
        else send(res,500,{error:"TEMPLATE_FAILED"});
      }
      return;
    }
    // Owner-scoped temporary artifact history. No DP access or activation.
    const revisionPrefix="/api/v1/parser-pairs/revisions/";
    if(path.startsWith(revisionPrefix)){
      const action=path.slice(revisionPrefix.length);
      if(!["register","list","download","diff","restore-preview"].includes(action)){
        send(res,404,{error:"NOT_FOUND"});return;
      }
      const isRead=action==="list"||action==="download";
      if(req.method!==(isRead?"GET":"POST")){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      const history=options.artifactRevisionHistory;
      const authorize=options.authorizeArtifactRevision;
      if(!history||!authorize){
        send(res,403,{error:"REVISION_HISTORY_DISABLED"});return;
      }
      let actor:RevisionOwner|null=null;
      try{actor=await authorize(req);}
      catch{/* Private authentication unavailable. */}
      if(!actor){
        send(res,403,{error:"REVISION_ACCESS_DENIED"});return;
      }
      const sendZip=(file:{zip:Buffer;filename:string;artifactRevisionId:string;
        zipSha256:string},restored=false)=>{
        res.writeHead(200,{
          "content-type":"application/zip",
          "content-disposition":'attachment; filename="'+file.filename+'"',
          "content-length":file.zip.length,
          "cache-control":"no-store",
          "x-content-type-options":"nosniff",
          "referrer-policy":"no-referrer",
          "x-frame-options":"DENY",
          "cross-origin-resource-policy":"same-origin",
          "x-parser-artifact-revision":file.artifactRevisionId,
          "x-parser-zip-sha256":file.zipSha256,
          ...(restored?{"x-parser-restore-status":"OFFLINE_RESTORE_PREVIEW"}:{}),
        });
        res.end(file.zip);
      };
      try{
        if(isRead){
          const query=new URL(req.url??"","http://localhost").searchParams;
          const key=action==="list"?"projectId":"artifactRevisionId";
          if([...query.keys()].some(k=>k!==key)||query.getAll(key).length!==1){
            send(res,422,{error:"REVISION_QUERY_INVALID"});return;
          }
          const id=query.get(key)!;
          if(action==="list"){
            send(res,200,{contract:"offline-revision-history.v0.1",
              revisions:history.list(actor,id),persistent:history.persistent,
              deploymentPerformed:false});
          }else sendZip(history.download(actor,id));
          return;
        }
        if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
          req.headers["content-type"]||"")){
          send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
        }
        const declared=Number(req.headers["content-length"]??0);
        if(!Number.isSafeInteger(declared)||declared<0||declared>MAX_IMPORT_BYTES){
          send(res,413,{error:"INPUT_TOO_LARGE"});return;
        }
        const raw=await jsonInput(req,MAX_IMPORT_BYTES);
        if(!raw||typeof raw!=="object"||Array.isArray(raw)){
          send(res,422,{error:"REVISION_REQUEST_INVALID"});return;
        }
        const data=raw as Record<string,unknown>;
        const exact=action==="register"?["pair","version"]:
          action==="diff"?["fromRevisionId","toRevisionId"]:
          ["previousRevisionId","expectedCurrentRevisionId"];
        if(Object.keys(data).sort().join(",")!==[...exact].sort().join(",")){
          send(res,422,{error:"REVISION_REQUEST_INVALID"});return;
        }
        if(action==="register"){
          send(res,200,history.register(actor,data["pair"] as PairExport,
            data["version"] as string));
        }else if(action==="diff"){
          send(res,200,history.diff(actor,data["fromRevisionId"] as string,
            data["toRevisionId"] as string));
        }else{
          sendZip(history.prepareRestore(actor,data["previousRevisionId"] as string,
            data["expectedCurrentRevisionId"] as string),true);
        }
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof ArtifactPackageError)
          send(res,422,{error:error.code});
        else if(error instanceof ArtifactRevisionHistoryError){
          const status=error.code==="REVISION_NOT_FOUND"?404:
            /DUPLICATE|CURRENT_CONFLICT|PROJECT_MISMATCH/.test(error.code)?409:
            error.code==="REVISION_CAPACITY_REACHED"?429:
            /INTEGRITY|FILE_UNSAFE|DIRECTORY_UNSAFE|STORE_LOCKED|STORE_IO_ERROR|AUDIT_CAPACITY|NOFOLLOW_UNAVAILABLE/.test(error.code)?503:
            error.code==="REVISION_ACTOR_INVALID"?403:422;
          send(res,status,{error:error.code,realTargetVerified:false});
        }else send(res,500,{error:"REVISION_REQUEST_FAILED"});
      }
      return;
    }
    // Opt-in, isolated mock transport: real target writes are not supported.
    // User input is metadata only; server independently resolves the artifact.
    const applyRoute="/api/v1/parser-pairs/target/apply";
    if(path===applyRoute||path===applyRoute+"/status"){
      const isStatus=path===applyRoute+"/status";
      if(req.method!==(isStatus?"GET":"POST")){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      const gateway=options.targetApplyMockGateway;
      if(!gateway){send(res,403,{error:"TARGET_APPLY_DISABLED"});return;}
      const actor=await gateway.authenticate(req);
      if(!actor){send(res,403,{error:"TARGET_APPLY_IDENTITY_DENIED"});return;}
      if(isStatus){
        try{
          const query=new URL(req.url??"", "http://localhost").searchParams;
          if([...query.keys()].some(k=>k!=="artifactRevisionId")||
             query.getAll("artifactRevisionId").length!==1){
            send(res,422,{error:"TARGET_APPLY_QUERY_INVALID"});return;
          }
          send(res,200,gateway.status(actor,query.get("artifactRevisionId")!));
        }catch{
          send(res,422,{error:"TARGET_APPLY_QUERY_INVALID"});
        }
        return;
      }
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      const maxBody=2048;
      const size=Number(req.headers["content-length"]??0);
      if(!Number.isSafeInteger(size)||size>maxBody||size<0){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const input=await jsonInput(req,maxBody);
        send(res,200,await gateway.apply(actor,input));
      }catch(error){
        const code=(error as {code?:string}).code??"";
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof TargetDeploymentError){
          const status=code==="TARGET_APPLY_REVISION_NOT_FOUND"?404:
            /VERSION_CONFLICT|NAME_CONFLICT|PORT_CONFLICT|IN_FLIGHT|REVISION_CONFLICT|SENSOR_CONF_PORT_MISMATCH/.test(code)?409:
            /DENIED|MOCK_TARGET_REQUIRED|CONFIRMATION_REQUIRED|CONFIRMATION_MISMATCH/.test(code)?403:
            /AUDIT_UNAVAILABLE|TARGET_UNAVAILABLE|INVENTORY_UNAVAILABLE|SENSOR_EVIDENCE_INCOMPLETE/.test(code)?503:
            /WRITE_UNCERTAIN|READBACK_UNVERIFIED|APPLY_FAILED/.test(code)?502:422;
          send(res,status,{error:code,realTargetVerified:false});
        }else send(res,502,{error:"TARGET_APPLY_FAILED",realTargetVerified:false});
      }
      return;
    }
    // Raw-data lookup uses a separate tenant/actor/audit grant, and is
    // never implied by the Legacy parser CRUD permission or HTTP status.
    const interflowPoll=path==="/api/v1/test-lab/interflow/poll";
    if(path==="/api/v1/test-lab/interflow/search"||interflowPoll){
      if(req.method!=="POST"){send(res,405,{error:"METHOD_NOT_ALLOWED"});return;}
      if(!options.legacyClient||!options.testLabController||
        !options.authorizeInterflowRead||!options.auditInterflowRead){
        send(res,403,{error:"INTERFLOW_SEARCH_DISABLED"});return;
      }
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]||0)>MAX_PROJECT_BYTES){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const input=await jsonInput(req,MAX_PROJECT_BYTES) as Record<string,unknown>;
        const expectedKeys=interflowPoll
          ? "endMs,expectedFields,index,intervalMs,limit,markerField,maxAttempts,runId,startMs"
          : "endMs,expectedFields,index,limit,markerField,runId,startMs";
        if(!input||typeof input!=="object"||Array.isArray(input)||
          Object.keys(input).sort().join(",")!==expectedKeys){
          send(res,422,{error:"INTERFLOW_REQUEST_INVALID"});return;
        }
        const request={
          index:input["index"],runId:input["runId"],
          markerField:input["markerField"],startMs:input["startMs"],
          endMs:input["endMs"],limit:input["limit"],
        } as Parameters<typeof options.legacyClient.searchInterflow>[0];
        // Validate query and expected-fields BEFORE any target request.
        const plan=buildInterflowQuery(options.legacyClient.tenant,request);
        const expected=input["expectedFields"] as Record<string,string|number|boolean>;
        compareInterflowHits({hits:{hits:[]}},plan,expected);
        // Every polling attempt independently checks data-read permission,
        // same run ownership and durable audit BEFORE contacting the DP.
        const readOne=async()=>{
          let actor:string|null=null;
          try{
            const principal=await options.authorizeInterflowRead!(req,plan.runId);
            if(typeof principal==="string"&&/^[A-Za-z0-9_.:@-]{1,128}$/.test(principal))
              actor=principal;
          }catch{/* Product raw-data read permission unavailable. */}
          if(!actor)throw new InterflowPollError("INTERFLOW_SEARCH_DENIED");
          try{options.testLabController!.status(plan.runId,actor);}
          catch{throw new InterflowPollError("INTERFLOW_RUN_NOT_FOUND");}
          try{
            await options.auditInterflowRead!({
              tenant:plan.tenant,runId:plan.runId,
              index:request.index,startMs:plan.startMs,endMs:plan.endMs,
              fieldNames:Object.keys(expected),
            });
          }catch{
            throw new InterflowPollError("INTERFLOW_AUDIT_UNAVAILABLE");
          }
          return options.legacyClient!.searchInterflow(request,expected);
        };
        if(interflowPoll){
          // HTTP client cancellation aborts sleeps immediately. Any pending
          // upstream GET has its own bounded deadline and never retries writes.
          const controller=new AbortController();
          const onClose=()=>controller.abort();
          res.once("close",onClose);
          try{
            const result=await pollBoundedInterflow(readOne,{
              maxAttempts:input["maxAttempts"] as number,
              intervalMs:input["intervalMs"] as number,
              signal:controller.signal,
            });
            if(!res.destroyed)send(res,200,result);
          }finally{
            res.off("close",onClose);
          }
        }else{
          const result=await readOne();
          send(res,200,result);
        }
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof InterflowContractError)
          send(res,422,{error:error.code});
        else if(error instanceof InterflowPollError){
          const status=error.code==="INTERFLOW_AUDIT_UNAVAILABLE"?503:
            error.code==="INTERFLOW_RUN_NOT_FOUND"?404:
            error.code==="INTERFLOW_SEARCH_DENIED"?403:
            error.code==="INTERFLOW_POLL_CANCELLED"?499:422;
          if(!res.destroyed)send(res,status,{error:error.code});
        }else if(!res.destroyed)mappedLegacyError(res,error);
      }
      return;
    }
    // Start/Pause/Resume/Stop are server-side lease controls over a
    // separately injected trusted sink; no configured sink => NO emission.
    const sessionPath="/api/v1/test-lab/sessions/";
    if(path.startsWith(sessionPath)){
      const action=path.slice(sessionPath.length);
      if(!["start","status","pause","resume","stop","renew","rate","evidence","evidence-export","evidence-summary"].includes(action)){
        send(res,404,{error:"NOT_FOUND"});return;
      }
      if(req.method!==((action==="status"||action==="evidence"||action==="evidence-export"||action==="evidence-summary")?"GET":"POST")){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      if(!options.testLabController||!options.authorizeTestLabSession){
        send(res,403,{error:"TESTLAB_SENDER_DISABLED"});return;
      }
      try{
        let runId:string|undefined;
        let input:Record<string,unknown>|undefined;
        if(action==="status"||action==="evidence"||action==="evidence-export"||action==="evidence-summary"){
          const query=new URL(req.url||"","http://localhost").searchParams;
          if([...query.keys()].some(x=>x!=="runId")||
            query.getAll("runId").length!==1){
            send(res,422,{error:"TESTLAB_SESSION_QUERY_INVALID"});return;
          }
          runId=query.get("runId")??undefined;
        }else{
          if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
            req.headers["content-type"]||"")){
            send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
          }
          if(Number(req.headers["content-length"]||0)>MAX_PROJECT_BYTES){
            send(res,413,{error:"INPUT_TOO_LARGE"});return;
          }
          input=await jsonInput(req,MAX_PROJECT_BYTES) as Record<string,unknown>;
          if(!input||typeof input!=="object"||Array.isArray(input)){
            send(res,422,{error:"TESTLAB_SESSION_INPUT_INVALID"});return;
          }
          const required=action==="start"?
            (Object.hasOwn(input,"scenario")?
              ["scenario","approvalId","ratePerSecond","leaseMs","maxEvents"]:
              ["sample","approvalId","ratePerSecond","leaseMs","maxEvents"]):
            action==="renew"?["runId","approvalId","leaseMs","additionalEvents"]:
            action==="rate"?["runId","approvalId","ratePerSecond"]:
            ["runId"];
          const permitted=action==="start"?
            [...required,"artifactRevisionId"]:required;
          if(Object.keys(input).some(key=>!permitted.includes(key))||
            required.some(key=>!Object.hasOwn(input!,key))){
            send(res,422,{error:"TESTLAB_SESSION_INPUT_INVALID"});return;
          }
          if(action!=="start")runId=input["runId"] as string;
        }
        if(action!=="start"&&!/^test_run_[0-9a-f]{32}$/.test(runId||"")){
          send(res,422,{error:"TESTLAB_SESSION_ID_INVALID"});return;
        }
        let actor:string|null=null;
        try{
          const resolved=await options.authorizeTestLabSession(req,runId);
          if(typeof resolved==="string"&&/^[A-Za-z0-9_.:@-]{1,128}$/.test(resolved))
            actor=resolved;
        }catch{/* Product auth store unavailable: reject. */}
        if(!actor){send(res,403,{error:"TESTLAB_SESSION_DENIED"});return;}
        const sessions=options.testLabController;
        if(action==="status"){send(res,200,sessions.status(runId!,actor));return;}
        if(action==="evidence"){send(res,200,sessions.evidenceReport(runId!,actor));return;}
        if(action==="evidence-summary"){
          send(res,200,summarizeRedactedEvidenceReport(
            sessions.evidenceReport(runId!,actor)));
          return;
        }
        if(action==="evidence-export"){
          const download=exportRedactedEvidenceReport(sessions.evidenceReport(runId!,actor));
          res.writeHead(200,{
            "content-type":"application/json; charset=utf-8",
            "content-disposition":'attachment; filename="'+download.filename+'"',
            "content-length":download.bytes.length,
            "x-parser-evidence-sha256":download.sha256,
            "cache-control":"no-store",
            "x-content-type-options":"nosniff",
            "referrer-policy":"no-referrer",
            "x-frame-options":"DENY",
            "cross-origin-resource-policy":"same-origin",
          });
          res.end(download.bytes);return;
        }
        if(action==="pause"){send(res,200,sessions.pause(runId!,actor));return;}
        if(action==="resume"){send(res,200,sessions.resume(runId!,actor));return;}
        if(action==="stop"){send(res,200,sessions.stop(runId!,actor));return;}
        if(action==="rate"){
          const request=input!;
          send(res,200,await sessions.changeRate(runId!,{
            approvalId:request["approvalId"] as string,
            ratePerSecond:request["ratePerSecond"] as number,
          },actor));
          return;
        }
        if(action==="renew"){
          const request=input!;
          const revised=await sessions.renew(runId!,{
            approvalId:request["approvalId"] as string,
            leaseMs:request["leaseMs"] as number,
            additionalEvents:request["additionalEvents"] as number,
          },actor);
          send(res,200,revised);
          return;
        }
        const data=input!;
        const result=await sessions.start({
          sample:data["sample"] as Parameters<typeof sessions.start>[0]["sample"],
          scenario:data["scenario"] as Parameters<typeof sessions.start>[0]["scenario"],
          approvalId:data["approvalId"] as string,
          ratePerSecond:data["ratePerSecond"] as number,
          leaseMs:data["leaseMs"] as number,
          maxEvents:data["maxEvents"] as number,
          artifactRevisionId:data["artifactRevisionId"] as string|undefined,
        },actor);
        send(res,200,result);
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof ScenarioContractError)
          send(res,422,{error:error.code});
        else if(error instanceof TestLabReportExportError){
          send(res,503,{error:error.code});
        }else if(error instanceof TestLabEvidenceError){
          send(res,error.code==="EVIDENCE_RUN_NOT_FOUND"?404:422,{error:error.code});
        }else if(error instanceof TestLabSessionError){
          const status=error.code==="TESTLAB_SESSION_NOT_FOUND"?404:
            error.code==="TESTLAB_CAPACITY_REACHED"?429:
            error.code==="TESTLAB_RENEWAL_IN_PROGRESS"||
            error.code==="TESTLAB_RATE_CHANGE_IN_PROGRESS"||
            error.code==="TESTLAB_RATE_CHANGE_IN_FLIGHT"?409:
            error.code==="TESTLAB_SENDER_SHUTDOWN"||
              error.code==="TESTLAB_JOURNAL_UNAVAILABLE"?503:
            /DISABLED|DENIED/.test(error.code)?403:422;
          send(res,status,{error:error.code});
        }else send(res,500,{error:"TESTLAB_SESSION_FAILED"});
      }
      return;
    }
    // Authenticated offline multi-family preview: no sender, credentials or
    // live run. Uses a fixed synthetic marker, not a caller-chosen session ID.
    if(path==="/api/v1/test-lab/scenario/preview"){
      if(req.method!=="POST"){send(res,405,{error:"METHOD_NOT_ALLOWED"});return;}
      let allowed=false;
      try{allowed=options.authorizeTestLabPreview!==undefined&&
        await options.authorizeTestLabPreview(req)===true;}
      catch{/* No preview rights on product auth failure. */}
      if(!allowed){send(res,403,{error:"TESTLAB_PREVIEW_NOT_AUTHORIZED"});return;}
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]||0)>MAX_PROJECT_BYTES){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const raw=await jsonInput(req,MAX_PROJECT_BYTES) as Record<string,unknown>;
        if(!raw||typeof raw!=="object"||Array.isArray(raw)||
          Object.keys(raw).sort().join(",")!=="ratePerSecond,scenario,sequence"){
          send(res,422,{error:"TESTLAB_SCENARIO_REQUEST_INVALID"});return;
        }
        const scenario=raw["scenario"] as ReplayScenario;
        const selected=selectScenarioPreview(scenario,
          raw["sequence"] as number,
          options.syntheticClock?.()??Date.now(),
          "test_run_00000000000000000000000000000000",
          raw["ratePerSecond"] as number);
        send(res,200,{
          ...selected,
          replayMode:scenario.mode,
          sampleFamilyCount:scenario.events.length,
          safeToSendToSensor:false,
          sensorReceivedVerified:false,
          runtimeParsingVerified:false,
        });
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof ScenarioContractError)send(res,422,{error:error.code});
        else send(res,500,{error:"TESTLAB_SCENARIO_FAILED"});
      }
      return;
    }
    // User-opt-in synthetic preview. In-memory only, no stream or sensor IO.
    if(path==="/api/v1/test-lab/preview"){
      if(req.method!=="POST"){send(res,405,{error:"METHOD_NOT_ALLOWED"});return;}
      let authorized=false;
      try{authorized=options.authorizeTestLabPreview!==undefined&&
        await options.authorizeTestLabPreview(req)===true;}
      catch{/* Fail closed if the product auth provider is unavailable. */}
      if(!authorized){send(res,403,{error:"TESTLAB_PREVIEW_NOT_AUTHORIZED"});return;}
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]||0)>MAX_PROJECT_BYTES){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const raw=await jsonInput(req,MAX_PROJECT_BYTES) as Record<string,unknown>;
        const fields=["format","source","seed","sequence","timestampField",
          "variableFields","runMarkerField","runId","csvColumns","csvDelimiter",
          "syslogBodyFormat"];
        if(!raw||typeof raw!=="object"||Array.isArray(raw)||
          Object.keys(raw).some(k=>!fields.includes(k))){
          send(res,422,{error:"TESTLAB_REQUEST_INVALID"});return;
        }
        const generated=createSyntheticPreview(
          raw as unknown as Parameters<typeof createSyntheticPreview>[0],
          options.syntheticClock?.()??Date.now());
        send(res,200,generated);
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof SyntheticPreviewError)send(res,422,{error:error.code});
        else send(res,500,{error:"TESTLAB_PREVIEW_FAILED"});
      }
      return;
    }
    // Offline ZIP download is independent from Legacy/DP configuration.
    // The request MUST carry the identical generated pair and manifest;
    // the package builder verifies exact compiler reproduction before zipping.
    if(path==="/api/v1/parser-pairs/package"){
      if(req.method!=="POST"){send(res,405,{error:"METHOD_NOT_ALLOWED"});return;}
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      if(Number(req.headers["content-length"]||0)>MAX_IMPORT_BYTES){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const input=await jsonInput(req,MAX_IMPORT_BYTES) as Record<string,unknown>;
        if(!input||typeof input!=="object"||Array.isArray(input)||
          Object.keys(input).sort().join(",")!=="pair,version"){
          send(res,422,{error:"ARTIFACT_REQUEST_INVALID"});return;
        }
        const result=buildArtifactPackage(input["pair"] as PairExport,input["version"] as string);
        res.writeHead(200,{
          "content-type":"application/zip",
          "content-disposition":'attachment; filename="'+result.filename+'"',
          "content-length":result.zip.length,
          "cache-control":"no-store",
          "x-content-type-options":"nosniff",
          "referrer-policy":"no-referrer",
          "x-frame-options":"DENY",
          "cross-origin-resource-policy":"same-origin",
          "x-parser-artifact-revision":result.manifest.artifactRevisionId,
          "x-parser-zip-sha256":result.zipSha256,
          "x-parser-listener-port":String(result.manifest.selectedParserPort),
        });
        res.end(result.zip);
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else if(error instanceof ArtifactPackageError)
          send(res,422,{error:error.code});
        else send(res,500,{error:"ARTIFACT_PACKAGE_FAILED"});
      }
      return;
    }
    // Exact public surface for Legacy-only POC integration. No modular
    // endpoint names are inferred from undocumented vendor APIs.
    const legacyBase="/api/v1/stellar/legacy/";
    if(path.startsWith(legacyBase)){
      const action=path.slice(legacyBase.length);
      if(action==="capabilities"){
        if(req.method!=="GET"){send(res,405,{error:"METHOD_NOT_ALLOWED"});return;}
        send(res,200,{...LEGACY_POC_CAPABILITIES,
          serviceConfigured:!!options.legacyClient,
          testWritesEnabled:!!(options.legacyClient&&options.legacyTestWritesEnabled&&
            options.authorizeLegacyRead&&options.legacyClient.toJSON().writesEnabled)});
        return;
      }
      const portProposal=action==="port-proposal";
      const list=action==="parsers"||action==="catalogue"||portProposal;
      const mutation=action==="create"||action==="update"||action==="delete";
      const prepare=action==="prepare";
      if(!list&&!mutation&&!prepare){send(res,404,{error:"NOT_FOUND"});return;}
      if(req.method!==(list?"GET":"POST")){
        send(res,405,{error:"METHOD_NOT_ALLOWED"});return;
      }
      if(mutation&&!options.legacyTestWritesEnabled){
        send(res,403,{error:"LEGACY_WRITES_DISABLED"});return;
      }
      if((list||mutation)&&!options.legacyClient){
        send(res,503,{error:"LEGACY_NOT_CONFIGURED"});return;
      }
      if(list||mutation){
        let allowed=false;
        try{
          allowed=options.authorizeLegacyRead!==undefined &&
            await options.authorizeLegacyRead(req)===true;
        }catch{/* Server operator's read grant failed; deny. */}
        if(!allowed){send(res,403,{error:"LEGACY_READ_DENIED"});return;}
      }
      if(list){
        try{
          if(action==="parsers"){
            const parsers=await options.legacyClient!.listParsers();
            send(res,200,{contract:"stellar-legacy-poc.v0.1",
              tenant:options.legacyClient!.tenant,parsers,
              runtimeParsingVerified:false,targetImportVerified:false});
          }else if(portProposal){
            const url=new URL(req.url||"","http://localhost");
            if([...url.searchParams.keys()].some(k=>k!=="port"&&k!=="format") ||
               url.searchParams.getAll("port").length>1 ||
               url.searchParams.getAll("format").length>1){
              send(res,422,{error:"PORT_QUERY_INVALID"});return;
            }
            const rawPort=url.searchParams.get("port");
            const rawFormat=url.searchParams.get("format");
            if((rawPort!==null&&!/^[0-9]{1,5}$/.test(rawPort)) ||
               (rawFormat!==null&&!["syslog_rfc3164","syslog_rfc5424"].includes(rawFormat))){
              send(res,422,{error:"PORT_QUERY_INVALID"});return;
            }
            const [catalogue,parsers]=await Promise.all([
              options.legacyClient!.listCatalogue(),options.legacyClient!.listParsers()
            ]);
            const trusted=options.portPlanningContext;
            const proposal=proposeParserPort({
              cataloguePorts:catalogue.map(x=>x.port).filter((x):x is number=>x!==undefined),
              tenantLegacyPorts:parsers.map(x=>x.port).filter((x):x is number=>x!==undefined),
              sensorParserPorts:trusted?.sensorParserPorts??[],
              localReservedPorts:trusted?.localReservedPorts??[],
              adminReservedPorts:trusted?.adminReservedPorts??[],
              evidence:{
                catalogueComplete:catalogue.every(x=>x.port!==undefined),
                tenantComplete:parsers.every(x=>x.port!==undefined),
                sensorBindingsComplete:trusted?.sensorBindingsComplete===true,
                reservationsComplete:trusted?.reservationsComplete===true,
              },
            },{
              ...(rawPort===null?{}:{requestedPort:Number(rawPort)}),
              ...(rawFormat===null?{}:{parserFormat:rawFormat as
                "syslog_rfc3164"|"syslog_rfc5424"}),
              ...(trusted?.rangeStart===undefined?{}:{rangeStart:trusted.rangeStart}),
              ...(trusted?.rangeEnd===undefined?{}:{rangeEnd:trusted.rangeEnd}),
            });
            send(res,200,proposal);
          }else{
            const catalogue=await options.legacyClient!.listCatalogue();
            send(res,200,{contract:"stellar-legacy-poc.v0.1",
              tenant:options.legacyClient!.tenant,catalogue,
              runtimeParsingVerified:false,targetImportVerified:false});
          }
        }catch(error){mappedLegacyError(res,error);}
        return;
      }
      if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(
        req.headers["content-type"]||"")){
        send(res,415,{error:"UNSUPPORTED_MEDIA_TYPE"});return;
      }
      const limit=MAX_IMPORT_BYTES;
      if(Number(req.headers["content-length"]||0)>limit){
        send(res,413,{error:"INPUT_TOO_LARGE"});return;
      }
      try{
        const input=await jsonInput(req,limit) as Record<string,unknown>;
        if(!input||typeof input!=="object"||Array.isArray(input)){
          send(res,422,{error:"LEGACY_INPUT_INVALID"});return;
        }
        const allowedKeys=action==="delete"?
          ["name","tenant","expectedVersion","confirmed","approvalId"]:
          ["pair","tenant","version","expectedVersion","confirmed","approvalId"];
        if(Object.keys(input).some(key=>!allowedKeys.includes(key))){
          send(res,422,{error:"LEGACY_INPUT_INVALID"});return;
        }
        const tenant=options.legacyClient?.tenant??input["tenant"];
        if(typeof tenant!=="string"||
          (input["tenant"]!==undefined&&input["tenant"]!==tenant)){
          send(res,422,{error:"POC_TENANT_MISMATCH"});return;
        }
        if(action==="delete"){
          const result=await options.legacyClient!.delete(input["name"] as string,{
            confirmed:input["confirmed"]===true,
            approvalId:input["approvalId"] as string,
            expectedVersion:input["expectedVersion"] as string,
          });
          send(res,200,result);return;
        }
        const plan=makeLegacyUploadPlan(input["pair"] as PairExport,
          tenant,input["version"] as string);
        if(prepare){
          let eligible=false;
          try{requireDisposablePocWrite(plan);eligible=true;}
          catch(error){if(!(error instanceof LegacyContractError))throw error;}
          send(res,200,{contract:"stellar-legacy-poc.v0.1",
            ...plan.toJSON(),testOnlyWriteEligible:eligible,
            apiRegistrationVerified:false,
            runtimeParsingVerified:false,targetImportVerified:false});
          return;
        }
        const confirmation={
          confirmed:input["confirmed"]===true,
          approvalId:input["approvalId"] as string,
          expectedVersion:input["expectedVersion"] as string,
        };
        const result=action==="create"
          ? await options.legacyClient!.create(plan,confirmation)
          : await options.legacyClient!.update(plan,confirmation);
        send(res,200,result);
      }catch(error){
        const code=(error as {code?:string}).code;
        if(code==="LIMIT")send(res,413,{error:"INPUT_TOO_LARGE"});
        else if(code==="JSON")send(res,400,{error:"INVALID_JSON"});
        else mappedLegacyError(res,error);
      }
      return;
    }
    const validate = path === "/api/v1/parser-pairs/validate";
    const generate = path === "/api/v1/parser-pairs/generate";
    const inspect = path === "/api/v1/parser-pairs/inspect";
    if (!validate && !generate && !inspect) { send(res, 404, {error:"NOT_FOUND"});return; }
    if (req.method !== "POST") { send(res, 405, {error:"METHOD_NOT_ALLOWED"});return; }
    if (!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(req.headers["content-type"] || "")) {
      send(res, 415, {error:"UNSUPPORTED_MEDIA_TYPE"});return;
    }
    const declaredLength = Number(req.headers["content-length"] || 0);
    const maxBytes = inspect ? MAX_IMPORT_BYTES : MAX_PROJECT_BYTES;
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      send(res, 413, {error:"INPUT_TOO_LARGE"});return;
    }
    try {
      const input = await jsonInput(req, maxBytes);
      if (inspect) {
        try {
          const inspected = inspectPair(input as { name: string; confContent: string; fragmentContent: string });
          send(res, 200, inspected);
        } catch (error) {
          if (error instanceof PairInspectionError) {
            const path = error.code === "PAIR_NAME_INVALID" ? "/name"
              : error.code === "PAIR_CONTENT_INVALID" ? "/files" : "/";
            send(res, 422, {error:"INVALID_PAIR",issues:[{
              code:error.code,path,message:error.message
            }]});
          } else {
            send(res, 500, {error:"INSPECTION_ERROR"});
          }
        }
        return;
      }
      const result = validateProject(input);
      if (validate) {
        send(res, result.ok ? 200 : 422, result);
        return;
      }
      if (!result.ok) {send(res, 422, {error:"INVALID_PROJECT",issues:result.issues});return;}
      send(res, 200, compilePair(input));
    } catch (error) {
      const code = (error as {code?:string}).code;
      if (code === "LIMIT") send(res, 413, {error:"INPUT_TOO_LARGE"});
      else if (code === "JSON") send(res, 400, {error:"INVALID_JSON"});
      else send(res, 500, {error:"GENERATION_ERROR"});
    }
  });
  // The network-facing server owns its injected in-memory Test Lab
  // controller. Closing the server cancels all timers and active sessions.
  if(options.testLabController)
    server.once("close",()=>options.testLabController!.stopAll());
  return server;
}
