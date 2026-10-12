import type { GeneratedPair } from './backendClient';
import type { BackendCapabilities } from './backendCapabilities';

const BASE='/api/v1/parser-pairs/package';
const HEX=/^[0-9a-f]{64}$/;
const PARSER_NAME=/^customized_[a-z][a-z0-9_]{1,47}$/;
const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_ZIP_BYTES=2*1024*1024;
const MAX_FILE_BYTES=512*1024;

export interface CheckedArtifactZip {
  filename:string;
  bytes:ArrayBuffer;
  sha256:string;
  size:number;
  artifactRevisionId:string;
  listenerPort:number;
}

/** Fail closed on old/misconfigured endpoints. A ZIP is a DRAFT download,
 * never an installation, deployment or target-verification command. */
export function assertPackageCapability(cap:BackendCapabilities):void {
  if (!cap.downloads || cap.downloads.zipWithManifest!==true ||
      cap.downloads.individualGeneratedFiles!==true ||
      cap.downloads.requiresDpConnection!==false ||
      cap.downloads.requiresApiKey!==false ||
      cap.downloads.autoDeploys!==false ||
      cap.downloads.exactArtifactRevision!==true) {
    throw new Error('The local backend does not support verified, non-deploying ZIP downloads.');
  }
}
async function sha256(bytes: string | ArrayBuffer):Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error('ZIP SHA-256 validation requires a secure browser context');
  const binary=typeof bytes==='string'?new TextEncoder().encode(bytes):bytes;
  const digest=await globalThis.crypto.subtle.digest('SHA-256',binary);
  return [...new Uint8Array(digest)].map(item=>item.toString(16).padStart(2,'0')).join('');
}
async function verifyPair(pair:GeneratedPair):Promise<{parserName:string;revision:number}> {
  if(!pair || pair.contract!=='host-customized-pair.v0.1' ||
     !pair.manifest || pair.manifest.contract!==pair.contract ||
     pair.manifest.status!=='DRAFT' || pair.manifest.schemaRevision!=='0.1' ||
     pair.manifest.engineVerified!==false || pair.manifest.targetImportVerified!==false ||
     !pair.manifest.projectId ||
     !Number.isSafeInteger(pair.manifest.projectRevision) ||
     Number(pair.manifest.projectRevision)<1 || Number(pair.manifest.projectRevision)>1_000_000 ||
     !Array.isArray(pair.files) || pair.files.length!==2 ||
     !pair.manifest.fileHashes || typeof pair.manifest.fileHashes!=='object') {
    throw new Error('The generated DRAFT files have an invalid contract or project revision.');
  }
  const parser=pair.files.find(file=>typeof file?.name==='string' && PARSER_NAME.test(file.name));
  if(!parser) throw new Error('A safe extensionless parser filename is required.');
  const config=pair.files.find(file=>file?.name===parser.name+'.conf');
  if(!config || parser===config || new Set(pair.files.map(file=>file.name)).size!==2) {
    throw new Error('The Ruby and CONF filenames must form a matching pair.');
  }
  if(Object.keys(pair.manifest.fileHashes).length!==2) {
    throw new Error('A SHA-256 manifest is required for both files.');
  }
  for(const file of pair.files) {
    if(typeof file.content!=='string' || !HEX.test(file.sha256) ||
       !Number.isSafeInteger(file.bytes) || file.bytes<1 || file.bytes>MAX_FILE_BYTES ||
       pair.manifest.fileHashes[file.name]!==file.sha256 ||
       new TextEncoder().encode(file.content).byteLength!==file.bytes ||
       await sha256(file.content)!==file.sha256) {
      throw new Error('ZIP packaging blocked: local DRAFT file hashes or byte lengths did not match.');
    }
  }
  return {parserName:parser.name,revision:pair.manifest.projectRevision!};
}

/** Explicit ZIP request after successful pair generation and feature discovery.
 * Checks the backend's deterministic ZIP filename, binary length, content
 * shape, SHA-256, intended receiver port and immutable package revision. */
export async function packageGeneratedPair(
  pair:GeneratedPair,
  version:string,
  capabilities:BackendCapabilities,
  expectedPort:number,
  requester:typeof fetch=fetch,
):Promise<CheckedArtifactZip> {
  assertPackageCapability(capabilities);
  if(typeof version!=='string' || !VERSION.test(version)) {
    throw new Error('Package version must be 1–64 ASCII alphanumeric characters, dots, hyphens, or underscores.');
  }
  if(!Number.isInteger(expectedPort) || expectedPort<1 || expectedPort>65535) {
    throw new Error('A valid listener port is not configured.');
  }
  const {parserName,revision}=await verifyPair(pair);
  const requestBody=JSON.stringify({pair,version});
  if(new TextEncoder().encode(requestBody).byteLength>MAX_ZIP_BYTES) {
    throw new Error('ZIP generation request exceeds the size limit.');
  }
  const response=await requester(BASE,{
    method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json',Accept:'application/zip'},
    body:requestBody,
  });
  if(response.status!==200) throw new Error('Backend ZIP generation denied (HTTP '+response.status+'). Individual files remain available.');
  const filename=parserName+'-r'+revision+'.zip';
  const contentType=response.headers.get('content-type');
  const disposition=response.headers.get('content-disposition');
  const sha=response.headers.get('x-parser-zip-sha256');
  const revisionId=response.headers.get('x-parser-artifact-revision');
  const declaredPort=response.headers.get('x-parser-listener-port');
  const declaredLength=response.headers.get('content-length');
  const bytesLength=Number(declaredLength);
  if(contentType!=='application/zip' ||
     disposition!=='attachment; filename="'+filename+'"' ||
     !sha || !HEX.test(sha) || !revisionId || !HEX.test(revisionId) ||
     declaredPort!==String(expectedPort) ||
     !declaredLength || !/^[1-9][0-9]*$/.test(declaredLength) ||
     !Number.isSafeInteger(bytesLength) || bytesLength>MAX_ZIP_BYTES) {
    throw new Error('ZIP filename, version, port, or integrity contract is invalid.');
  }
  const bytes=await response.arrayBuffer();
  const data=new Uint8Array(bytes);
  const end=data.length-22;
  if(bytes.byteLength!==bytesLength || data.length<30 ||
     data[0]!==0x50 || data[1]!==0x4b || data[2]!==0x03 || data[3]!==0x04 ||
     end<0 || data[end]!==0x50 || data[end+1]!==0x4b ||
     data[end+2]!==0x05 || data[end+3]!==0x06 ||
     await sha256(bytes)!==sha) {
    throw new Error('ZIP download blocked due to invalid response format, size, or SHA-256.');
  }
  return {filename,bytes,size:bytesLength,sha256:sha,
    artifactRevisionId:revisionId,listenerPort:expectedPort};
}
