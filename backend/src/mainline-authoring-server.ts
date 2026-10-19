import {createServer,type Server} from "node:http";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {createBackendServer} from "./http.js";
import {BACKEND_CAPABILITIES} from "./capabilities.js";

/**
 * Parser Studio's shipped backend is for OFFLINE parser authoring only.
 * Reuse the qualified compiler and validators verbatim, but never route
 * traffic to the historical Test Lab, sensor, DP or Interflow handlers.
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

/**
 * A route-level allowlist is not enough if /capabilities still advertises
 * historical Test Lab, native verification, or owner-revision endpoints.
 * Project only the exact reviewed authoring subset, retaining the strict
 * consumer capability contract without claiming disabled target operations.
 */
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

export function isMainlineAuthoringRoute(path:string,method:string):boolean{
  // HTTP request targets are untrusted. Even a frozen ordinary object still
  // inherits constructor/toString/__proto__; never invoke their properties
  // as though they were allowlisted method arrays.
  return Object.hasOwn(ALLOWED,path)&&ALLOWED[path]?.includes(method)===true;
}

export function createMainlineAuthoringServer():Server{
  const core=createBackendServer();
  return createServer((request,response)=>{
    const path=(request.url??"").split("?")[0]??"";
    if(!isMainlineAuthoringRoute(path,request.method??"")){
      // Never echo untrusted paths or bodies, or expose restricted handlers.
      response.writeHead(404,{
        "content-type":"application/json; charset=utf-8",
        "cache-control":"no-store",
        "x-content-type-options":"nosniff",
      });
      response.end(JSON.stringify({error:"AUTHORING_ONLY_ROUTE_NOT_AVAILABLE"}));
      return;
    }
    if(path==="/api/v1/parser-pairs/capabilities"){
      response.writeHead(200,{
        "content-type":"application/json; charset=utf-8",
        "cache-control":"no-store",
        "x-content-type-options":"nosniff",
      });
      response.end(JSON.stringify(MAINLINE_AUTHORING_CAPABILITIES));
      return;
    }
    core.emit("request",request,response);
  });
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const port=Number(process.env["PARSER_BACKEND_PORT"]??"4179");
  if(!Number.isSafeInteger(port)||port<1024||port>65535)
    throw new Error("PARSER_BACKEND_PORT must be a valid unprivileged TCP port");
  createMainlineAuthoringServer().listen(port,"127.0.0.1",()=>{
    process.stdout.write("Parser Studio offline authoring backend listening on 127.0.0.1:"+port+"\n");
  });
}
