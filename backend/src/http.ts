import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { TextDecoder } from "node:util";
import { compilePair } from "./compiler.js";
import { BACKEND_CAPABILITIES } from "./capabilities.js";
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
    return JSON.parse(source) as unknown;
  }
  catch { throw Object.assign(new Error("Invalid JSON request"), {code: "JSON"}); }
}

/**
 * Private local integration endpoint. No network listener is opened until
 * a caller invokes server.listen. When run from the CLI, binds loopback only.
 */
export function createBackendServer(): Server {
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
