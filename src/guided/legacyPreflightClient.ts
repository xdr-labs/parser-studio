import type { GeneratedPair } from './backendClient';

/** Read-only, same-origin Legacy paired-upload dry run. Never calls POC
 * create/update/delete, auth configuration, remote DP or sensor endpoints.
 * The backend validates exact pair format but does NOT test target import. */
export interface LegacyPreflightResult {
  name: string;
  tenant: string;
  version: string;
  port: number;
  parserHash: string;
  confHash: string;
  matchedHashes: true;
  testOnlyWriteEligible: boolean;
  apiRegistrationVerified: false;
  runtimeParsingVerified: false;
  targetImportVerified: false;
  deploymentPerformed: false;
}
const NAME=/^customized_[a-z][a-z0-9_]{1,47}$/;
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HEX=/^[0-9a-f]{64}$/;
const MAX_PAIR_BYTES=2*1024*1024;

function exact(value: unknown, fields: readonly string[]): value is Record<string,unknown> {
  return typeof value==='object' && value!==null && !Array.isArray(value) &&
    Object.keys(value).length===fields.length &&
    Object.keys(value).every(field=>fields.includes(field));
}
async function digest(data:string):Promise<string> {
  if(!globalThis.crypto?.subtle) throw new Error('SHA-256 validation requires a secure browser context');
  const hash=await globalThis.crypto.subtle.digest('SHA-256',new TextEncoder().encode(data));
  return [...new Uint8Array(hash)].map(n=>n.toString(16).padStart(2,'0')).join('');
}
function requirePort(port:unknown):asserts port is number {
  if(typeof port!=='number'||!Number.isInteger(port)||port<1024||port>65535)
    throw new Error('Parser listener port is invalid; no Legacy preflight was performed.');
}
async function verifiedPair(pair:GeneratedPair, expectedPort:number) {
  requirePort(expectedPort);
  if(!pair || pair.contract!=='host-customized-pair.v0.1'||
     !pair.manifest || pair.manifest.status!=='DRAFT' ||
     pair.manifest.contract!==pair.contract ||
     pair.manifest.schemaRevision!=='0.1' ||
     pair.manifest.engineVerified!==false ||
     pair.manifest.targetImportVerified!==false ||
     !Array.isArray(pair.files)||pair.files.length!==2 ||
     !pair.manifest.fileHashes || typeof pair.manifest.fileHashes!=='object') {
    throw new Error('No verified DRAFT paired artifact is available for a Legacy dry run');
  }
  const parser=pair.files.find(f=>typeof f?.name==='string'&&NAME.test(f.name));
  if(!parser)throw new Error('No safely named extensionless parser is available');
  const conf=pair.files.find(f=>f?.name===parser.name+'.conf');
  if(!conf || conf===parser || new Set(pair.files.map(f=>f.name)).size!==2 ||
     Object.keys(pair.manifest.fileHashes).length!==2)
    throw new Error('CONF and extensionless parser filenames do not match');
  for(const f of [parser,conf]){
    if(typeof f.content!=='string'||!HEX.test(f.sha256)||
       !Number.isInteger(f.bytes)||f.bytes<=0||f.bytes>512000||
       new TextEncoder().encode(f.content).byteLength!==f.bytes||
       pair.manifest.fileHashes[f.name]!==f.sha256||
       await digest(f.content)!==f.sha256) {
      throw new Error('Generated source pair does not match its SHA-256 manifest');
    }
  }
  const ports=[...conf.content.matchAll(/^\s*port\s+(\d+)\s*$/gm)]
    .map(match=>Number(match[1]));
  if(!ports.length||ports.some(port=>port!==expectedPort))
    throw new Error('Generated CONF does not match the current selected parser listener port');
  return {parser,conf};
}

export async function prepareLegacyUploadPlan(
  pair:GeneratedPair,
  tenant:string,
  version:string,
  receiverPort:number,
  requester:typeof fetch=fetch,
):Promise<LegacyPreflightResult> {
  if(typeof tenant!=='string' || !TENANT.test(tenant))
    throw new Error('Legacy tenant identifier must contain 1–128 letters, numbers, underscores or hyphens');
  if(typeof version!=='string' || !VERSION.test(version))
    throw new Error('Legacy version must be 1–64 safe characters without paths');
  const {parser,conf}=await verifiedPair(pair,receiverPort);
  const payload=JSON.stringify({pair,tenant,version});
  if(new TextEncoder().encode(payload).byteLength>MAX_PAIR_BYTES)
    throw new Error('Legacy preflight request is too large');
  const response=await requester('/api/v1/stellar/legacy/prepare',{
    method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json',Accept:'application/json'},
    body:payload,
  });
  if(response.status!==200)
    throw new Error('Legacy dry-run API rejected the artifact (HTTP '+response.status+'); no deployment performed');
  let json:unknown;
  try{json=await response.json();}
  catch{throw new Error('Legacy dry-run backend did not return valid JSON');}
  const fields=['contract','name','tenant','version','port','filenames','proof',
    'testOnlyWriteEligible','apiRegistrationVerified','runtimeParsingVerified','targetImportVerified'];
  const proofKeys=['parserSha256','confSha256','status','runtimeParsingVerified','targetImportVerified'];
  if(!exact(json,fields)||
    json.contract!=='stellar-legacy-poc.v0.1' ||
    json.name!==parser.name||json.tenant!==tenant||json.version!==version||
    json.port!==receiverPort||!Array.isArray(json.filenames)||
    json.filenames.length!==2||new Set(json.filenames).size!==2||
    !json.filenames.includes(parser.name)||!json.filenames.includes(conf.name)||
    typeof json.testOnlyWriteEligible!=='boolean' ||
    json.apiRegistrationVerified!==false ||
    json.runtimeParsingVerified!==false ||
    json.targetImportVerified!==false ||
    !exact(json.proof,proofKeys)||
    json.proof.parserSha256!==parser.sha256||
    json.proof.confSha256!==conf.sha256||
    json.proof.status!=='DRAFT'||
    json.proof.runtimeParsingVerified!==false||
    json.proof.targetImportVerified!==false) {
    throw new Error('Legacy dry-run response contradicts the exact SHA-256 pair or unverifiable status');
  }
  return {
    name:parser.name,tenant,version,port:receiverPort,
    parserHash:parser.sha256,confHash:conf.sha256,
    matchedHashes:true,
    testOnlyWriteEligible:json.testOnlyWriteEligible,
    apiRegistrationVerified:false,runtimeParsingVerified:false,
    targetImportVerified:false,deploymentPerformed:false,
  };
}
