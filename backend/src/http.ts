import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { TextDecoder } from "node:util";
import { hasValidUnicodeJson } from "./unicode.js";
import { compilePair } from "./compiler.js";
import { BACKEND_CAPABILITIES } from "./capabilities.js";
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
  legacyClient?:LegacyPocClient;
  authorizeLegacyRead?:(request:IncomingMessage)=>Promise<boolean>;
  legacyTestWritesEnabled?:boolean;
}

function mappedLegacyError(res:ServerResponse,error:unknown):void{
  if(error instanceof LegacyApiError){
    send(res,502,{error:"LEGACY_UPSTREAM_HTTP",operation:error.method,
      upstreamStatus:error.httpStatus,runtimeParsingVerified:false});
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
  return createServer(async (req, res) => {
    const path = req.url?.split("?")[0] || "";
    if (path === "/health" && req.method === "GET") {
      send(res, 200, {status:"ok", service:"parser-pair-backend", version:"0.1"});
      return;
    }
    if (path === "/api/v1/parser-pairs/schema" && req.method === "GET") {
      send(res, 200, projectSchema);
      return;
    }
    if (path === "/api/v1/parser-pairs/capabilities") {
      if (req.method !== "GET") {
        send(res, 405, {error: "METHOD_NOT_ALLOWED"});
      } else {
        send(res, 200, BACKEND_CAPABILITIES);
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
      const list=action==="parsers"||action==="catalogue";
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
}
