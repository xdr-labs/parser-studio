/**
 * Provenance-checked Legacy paired-file transport plan and POC-only write gate.
 *
 * Derived from the independently validated PR #10 Python reference contract.
 * No credential handling, Ruby evaluation, API connection or upload here.
 * Generic generated files are always reviewable/read-only by default.
 */
import {createHash} from "node:crypto";
import {compilePair} from "./compiler.js";
import {validateProject} from "./validate.js";
import {hasValidUnicodeJson} from "./unicode.js";
import type {PairExport, ParserProject, ExportFile} from "./types.js";

const sha256=(source:string)=>createHash("sha256").update(source,"utf8").digest("hex");
const SLUG=/^customized_[a-z][a-z0-9_]{1,47}$/;
const TEST_NAME=/^customized_ps_api_crud_test_[0-9a-f]{6,16}$/;
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const VERSION=/^[A-Za-z0-9._/-]{1,64}$/;
const FILE_HASH=/^[0-9a-f]{64}$/;
const B64_CALL=/Base64\.strict_decode64\('([A-Za-z0-9+/=]{8,35000})'\)/g;
const KNOWN_TEMPLATES=new Set([
  // Reviewed fixed mixed CSV schema; synthetic Native only, no vendor E2E.
  "90c6582bb7bf7d5d18537fc84f517b7b4eb3d81d965c2929227b3f939f1d0664",
  // Bounded Java LF LF native-reviewed parser template SHA; target not verified.
  "597a6c8e47c2958f9fc3e3040a2470a8cea4f87ce863ca10cb98e97551a542a9",
  // Strict RFC3164 CEF/LEEF allowlisted mixed decoder; Native synthetic-only SHA.
  "893d1f11f7e2eb7c595867527eb52f7d077aa86dd762733083b976c87d4740ff",
  // Strict reviewed RFC5424 JSON/KV mixed decoder; Native synthetic-only SHA.
  "d77bdde4fe8c2a1bba4fc149f58ab5b2514f60047251c5389d074fc43ae6fc79",
  // RFC3164 TAG: KV allowlisted mixed grammar native-qualified public-synthetic only.
  "5fa3104a85a040bfe25e07170f835b3e335c9e99922624e9228b1844ded3f4a6",
  // Reviewed RFC5424-CEF/LEEF strict mixed dispatch template (native-qualified synthetic only).
  "92375061dca52ae232177a20fd7f5cb007a262ccdcac938d7225d1bb96618a2f",
  "e56812e5efd75ddc255e0813ecbd02f675bfb7b85928b35ff0db6b472791044e",
  "e941f631da790103cc4c53a89e2eebca2b5df470300935690ebd3450d2e4e911",
  // Reviewed RFC3164-only addition; exact template SHA, still recompiled and byte-compared.
  "50273e4385909eaf41c52057477e739de3e38ea36377b346fed7ce0471cda923",
  // Reviewed RFC3164 + strict quote-safe KV parsing; exact hash, no dynamic trust.
  "6f7c53255f431b7f51ab09cb66a32750b43cd9d881335d1e3d4251b563058676",
  // Reviewed strict mixed family dispatcher, exact template bytes only.
  "032a6b92c962cc0e9ad70f9c91e545b967d299c83036170eb3ac63950001db02",
]);

export const LEGACY_POC_CAPABILITIES=Object.freeze({
  contract:"stellar-legacy-poc.v0.1",
  legacyPairCrudVerifiedOnPoc:true,
  modularUploadVerified:false,
  activationApiVerified:false,
  runtimeParsingVerified:false,
  legacyUploadMayBeActiveImmediately:true,
  generalDeploymentEnabled:false,
  pocWritesEnabledByDefault:false,
  testWritesRequireBackendApproval:true,
  targetImportVerified:false,
  allowedHost:"https://poc-apac.stellarcyber.cloud",
  reservedPortMin:7800, reservedPortMax:7999,
});

export class LegacyContractError extends Error {
  constructor(readonly code:string) {super(code);this.name="LegacyContractError";}
}
function fail(code:string):never{throw new LegacyContractError(code);}
export type LegacyPortProtocols={port:number;protocols:readonly ("udp"|"tcp")[]};
export type DisposablePocProof=LegacyPortProtocols&{
  templateSha256:string;syntheticFixtureOnly:true;runtimeParsingVerified:false;
};

function checkFile(record:ExportFile):{name:string;bytes:Buffer;digest:string}{
  if(!record||typeof record!=="object"||typeof record.name!=="string"||
     !/^[A-Za-z0-9_.-]{1,96}$/.test(record.name)||
     typeof record.content!=="string"||!hasValidUnicodeJson(record.content))fail("POC_FILE_INVALID");
  const bytes=Buffer.from(record.content,"utf8");
  if(!bytes.length||bytes.length>512000||record.bytes!==bytes.length||
    typeof record.sha256!=="string"||!FILE_HASH.test(record.sha256)||
    sha256(record.content)!==record.sha256)fail("POC_FILE_INTEGRITY");
  return {name:record.name,bytes,digest:record.sha256};
}

function inspectConfiguration(text:string,tenant:string):number{
  if(Buffer.byteLength(text,"utf8")>12000||text.includes("\0")||text.includes("\r"))
    fail("POC_CONF_UNSAFE");
  if(!text.includes("<source>")||!text.includes("</source>"))
    fail("POC_CONF_UNSAFE");
  const ports=Array.from(text.matchAll(/^\s*port\s+(\d+)\s*$/gm),m=>Number(m[1]));
  if(!ports.length||ports.some(p=>!Number.isInteger(p)||p<1||p>65535||p!==ports[0]))
    fail("POC_PORT_UNSAFE");
  const cust=Array.from(text.matchAll(/^\s*cust_id\s+['"]?([a-zA-Z0-9_-]+)/gm),m=>m[1]);
  if(cust.some(c=>c!==tenant))fail("POC_TENANT_MISMATCH");
  return ports[0]!;
}

/** The full file sources reside in #private slots; JSON/UI output contains only hashes. */
export class LegacyUploadPlan {
  #ruby:Buffer;
  #conf:Buffer;
  readonly name:string;
  readonly tenant:string;
  readonly version:string;
  readonly port:number;
  readonly filenames: string[];
  readonly parserSha256:string;
  readonly confSha256:string;
  readonly proof:{
    parserSha256:string;confSha256:string;
    status:"DRAFT";targetImportVerified:false;runtimeParsingVerified:false;
  };
  constructor(pair:PairExport,tenant:string,version:string){
    if(typeof tenant!=="string"||!TENANT.test(tenant))fail("POC_TENANT_INVALID");
    if(typeof version!=="string"||!VERSION.test(version))fail("POC_VERSION_INVALID");
    if(!pair||pair.contract!=="host-customized-pair.v0.1"||
      !pair.manifest||pair.manifest.contract!==pair.contract||
      pair.manifest.schemaRevision!=="0.1"||pair.manifest.status!=="DRAFT"||
      pair.manifest.targetImportVerified!==false||
      pair.manifest.engineVerified!==false||
      !Array.isArray(pair.files)||pair.files.length!==2)fail("POC_MANIFEST_INVALID");
    const checked=pair.files.map(checkFile);
    const parser=checked.find(f=>SLUG.test(f.name));
    if(!parser||checked.filter(f=>f.name===parser.name).length!==1)
      fail("POC_NAME_INVALID");
    const conf=checked.find(f=>f.name===parser.name+".conf");
    if(!conf||new Set(checked.map(f=>f.name)).size!==2)
      fail("POC_PAIR_INVALID");
    const hashes=pair.manifest.fileHashes;
    if(!hashes||typeof hashes!=="object"||Object.keys(hashes).length!==2||
      hashes[parser.name]!==parser.digest||hashes[conf.name]!==conf.digest)
      fail("POC_MANIFEST_HASH");
    this.name=parser.name;this.tenant=tenant;this.version=version;
    this.port=inspectConfiguration(conf.bytes.toString("utf8"),tenant);
    this.#ruby=Buffer.from(parser.bytes);this.#conf=Buffer.from(conf.bytes);
    this.parserSha256=parser.digest;this.confSha256=conf.digest;
    this.filenames=[parser.name,conf.name];
    this.proof=Object.freeze({
      parserSha256:parser.digest,confSha256:conf.digest,status:"DRAFT" as const,
      targetImportVerified:false as const,runtimeParsingVerified:false as const,
    });
  }
  /** Only the authenticated server-side transport uses these bytes. */
  multipartFiles():readonly {filename:string;body:Buffer;type:string}[]{
    return [
      {filename:this.name,body:Buffer.from(this.#ruby),type:"application/octet-stream"},
      {filename:this.name+".conf",body:Buffer.from(this.#conf),type:"text/plain"},
    ];
  }
  toJSON(){
    return {name:this.name,tenant:this.tenant,version:this.version,port:this.port,
      filenames:[...this.filenames],proof:this.proof};
  }
}
export function makeLegacyUploadPlan(pair:PairExport,tenant:string,version:string):LegacyUploadPlan{
  return new LegacyUploadPlan(pair,tenant,version);
}

function reviewedRuby(ruby:Buffer,name:string,port:number,protocols:readonly string[]):string{
  const text=ruby.toString("utf8");
  const matches=Array.from(text.matchAll(B64_CALL));
  if(matches.length!==1)fail("POC_RUBY_UNREVIEWED");
  const token=matches[0]![1]!;
  const normalized=text.replace(token,"__PARSER_PROJECT_B64__");
  const templateSha=sha256(normalized);
  if(!KNOWN_TEMPLATES.has(templateSha))fail("POC_RUBY_UNREVIEWED");
  const decoded=Buffer.from(token,"base64");
  if(!decoded.length||decoded.length>24000||decoded.toString("base64")!==token)
    fail("POC_RUBY_IR_INVALID");
  let project:ParserProject;
  try{
    project=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(decoded)) as ParserProject;
  }catch{fail("POC_RUBY_IR_INVALID");}
  const validation=validateProject(project);
  if(!validation.ok||project.projectId!=="synthetic-fixture"||
    project.schemaRevision!=="0.1"||project.vendor!=="Synthetic"||
    project.slug!==(name.slice("customized_".length))||
    project.receiver.bindAddress!=="127.0.0.1"||
    project.receiver.port!==port||
    project.receiver.tcpFraming!=="line"||
    JSON.stringify(project.receiver.protocols)!==JSON.stringify(protocols))
    fail("POC_RUBY_IR_INVALID");
  if(compilePair(project).files.find(f=>f.name===name)?.content!==text)
    fail("POC_RUBY_UNREVIEWED");
  return templateSha;
}

/** Exact closed grammar: no includes, filters, routes, labels or public listeners. */
function disposableConfig(name:string,port:number,protocols:readonly string[]):string{
  const lines:string[]=[];
  for(const protocol of protocols){
    if(protocol!=="udp"&&protocol!=="tcp")fail("POC_CONF_UNSAFE");
    lines.push("<source>","@type "+protocol,"bind 127.0.0.1","port "+port,
      "tag "+name,"<parse>","@type "+name,"</parse>","</source>");
  }
  lines.push("<match "+name+".**>","@type null","</match>");
  return lines.join("\n")+"\n";
}

export function requireDisposablePocWrite(plan:LegacyUploadPlan):DisposablePocProof{
  if(!(plan instanceof LegacyUploadPlan))fail("POC_PLAN_INVALID");
  if(!TEST_NAME.test(plan.name))fail("POC_NAME_UNSAFE");
  if(plan.port<7800||plan.port>7999)fail("POC_PORT_UNSAFE");
  const files=plan.multipartFiles();
  const conf=files[1]!.body.toString("utf8");
  // A closed structural grammar is stricter than the source Python parser.
  let protocols:("udp"|"tcp")[]=[];
  const match=conf.matchAll(/^@type (udp|tcp)$/gm);
  protocols=Array.from(match,m=>m[1] as "udp"|"tcp");
  if(!protocols.length||protocols.length>2||
     new Set(protocols).size!==protocols.length||
     conf!==disposableConfig(plan.name,plan.port,protocols))
    fail("POC_CONF_UNSAFE");
  const templateSha256=reviewedRuby(files[0]!.body,plan.name,plan.port,protocols);
  return {port:plan.port,protocols,templateSha256,
    syntheticFixtureOnly:true,runtimeParsingVerified:false};
}

/** Explicitly built test-only artifacts; NEVER rewrite a general downloaded pair. */
export function makeDisposablePocTestPair(input:ParserProject):PairExport{
  const validation=validateProject(input);
  if(!validation.ok||input.projectId!=="synthetic-fixture"||
    input.vendor!=="Synthetic"||!TEST_NAME.test("customized_"+input.slug)||
    input.receiver.port<7800||input.receiver.port>7999||
    input.receiver.bindAddress!=="127.0.0.1"||input.receiver.tcpFraming!=="line")
    fail("POC_DISPOSABLE_PROJECT_REQUIRED");
  const generated=compilePair(input);
  const confContent=disposableConfig("customized_"+input.slug,input.receiver.port,input.receiver.protocols);
  const conf:ExportFile={name:"customized_"+input.slug+".conf",content:confContent,
    sha256:sha256(confContent),bytes:Buffer.byteLength(confContent,"utf8")};
  const ruby=generated.files.find(f=>f.name==="customized_"+input.slug)!;
  return {...generated,files:[conf,ruby],
    manifest:{...generated.manifest,fileHashes:{[conf.name]:conf.sha256,[ruby.name]:ruby.sha256},
      warnings:[...generated.manifest.warnings,
        "TEST-ONLY POC LOOPBACK NULL SINK. Upload may immediately activate a Legacy parser.",
        "General/custom parser deployment is NOT authorized."]}};
}
