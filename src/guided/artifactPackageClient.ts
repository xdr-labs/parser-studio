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
    throw new Error('현재 로컬 백엔드는 검증된 비배포 ZIP 패키지 다운로드를 제공하지 않습니다.');
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
    throw new Error('이미 생성된 DRAFT 파일의 계약 또는 프로젝트 리비전이 유효하지 않습니다.');
  }
  const parser=pair.files.find(file=>typeof file?.name==='string' && PARSER_NAME.test(file.name));
  if(!parser) throw new Error('안전한 확장자 없는 파서 파일 이름이 필요합니다.');
  const config=pair.files.find(file=>file?.name===parser.name+'.conf');
  if(!config || parser===config || new Set(pair.files.map(file=>file.name)).size!==2) {
    throw new Error('동일한 이름의 Ruby/CONF 파일 쌍이 필요합니다.');
  }
  if(Object.keys(pair.manifest.fileHashes).length!==2) {
    throw new Error('두 파일의 SHA-256 매니페스트가 필요합니다.');
  }
  for(const file of pair.files) {
    if(typeof file.content!=='string' || !HEX.test(file.sha256) ||
       !Number.isSafeInteger(file.bytes) || file.bytes<1 || file.bytes>MAX_FILE_BYTES ||
       pair.manifest.fileHashes[file.name]!==file.sha256 ||
       new TextEncoder().encode(file.content).byteLength!==file.bytes ||
       await sha256(file.content)!==file.sha256) {
      throw new Error('로컬 DRAFT 파일의 해시 또는 길이가 불일치하여 ZIP 전송을 차단했습니다.');
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
    throw new Error('패키지 버전은 1–64자의 영문·숫자·점·하이픈·밑줄만 허용합니다.');
  }
  if(!Number.isInteger(expectedPort) || expectedPort<1 || expectedPort>65535) {
    throw new Error('유효한 수신 포트가 설정돼 있지 않습니다.');
  }
  const {parserName,revision}=await verifyPair(pair);
  const requestBody=JSON.stringify({pair,version});
  if(new TextEncoder().encode(requestBody).byteLength>MAX_ZIP_BYTES) {
    throw new Error('ZIP 생성 요청의 최대 크기를 초과했습니다.');
  }
  const response=await requester(BASE,{
    method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json',Accept:'application/zip'},
    body:requestBody,
  });
  if(response.status!==200) throw new Error('백엔드 ZIP 생성 거부 (HTTP '+response.status+'). 개별 파일은 그대로 유지됩니다.');
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
    throw new Error('ZIP 파일 이름·버전·포트·무결성 계약을 확인할 수 없습니다.');
  }
  const bytes=await response.arrayBuffer();
  const data=new Uint8Array(bytes);
  const end=data.length-22;
  if(bytes.byteLength!==bytesLength || data.length<30 ||
     data[0]!==0x50 || data[1]!==0x4b || data[2]!==0x03 || data[3]!==0x04 ||
     end<0 || data[end]!==0x50 || data[end+1]!==0x4b ||
     data[end+2]!==0x05 || data[end+3]!==0x06 ||
     await sha256(bytes)!==sha) {
    throw new Error('ZIP 응답의 형식·크기·SHA-256 불일치로 다운로드를 차단했습니다.');
  }
  return {filename,bytes,size:bytesLength,sha256:sha,
    artifactRevisionId:revisionId,listenerPort:expectedPort};
}
