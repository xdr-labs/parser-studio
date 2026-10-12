/** Opt-in, same-origin, owner-authorized OFFLINE parser-artifact history only.
 * These requests cannot apply a parser, deploy to a DP, or read customer logs.
 * Reject unexpected backend fields before returning data to the interface.
 */
import type {GeneratedPair} from './backendClient';
import {verifyGeneratedPair} from './artifactPackageClient';

const BASE='/api/v1/parser-pairs/revisions/';
const SHA=/^[0-9a-f]{64}$/;
const PROJECT=/^[A-Za-z0-9_.-]{1,128}$/;
const PARSER=/^customized_[a-z][a-z0-9_]{1,47}$/;
const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_BYTES=2*1024*1024;

export interface RevisionSummary {
  artifactRevisionId:string;
  parserName:string;
  projectId:string;
  projectRevision:number;
  version:string;
  selectedParserPort:number;
  receiverProtocols:('udp'|'tcp')[];
  fileHashes:Record<string,string>;
  zipSha256:string;
  createdAt:string;
  targetImportVerified:false;
  deploymentPerformed:false;
}
export interface RevisionDiff {
  contract:'offline-artifact-diff.v0.1';
  fromRevisionId:string;toRevisionId:string;projectId:string;
  version:{from:string;to:string;changed:boolean};
  selectedParserPort:{from:number;to:number;changed:boolean};
  files:{name:string;fromSha256:string|null;toSha256:string|null;changed:boolean}[];
  realTargetVerified:false;appliesToDp:false;
}
export interface VerifiedRevisionZip {
  artifactRevisionId:string;
  filename:string;
  bytes:ArrayBuffer;
  sha256:string;
  previewOnly:boolean;
}

function record(value:unknown):Record<string,unknown> {
  if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.getPrototypeOf(value)!==Object.prototype)throw new Error('Invalid offline revision contract.');
  return value as Record<string,unknown>;
}
function exact(value:unknown,keys:string[]):Record<string,unknown>{
  const obj=record(value);
  if(Object.keys(obj).sort().join('|')!==[...keys].sort().join('|'))
    throw new Error('Unexpected offline revision response fields.');
  return obj;
}
function validPort(value:unknown):value is number{
  return typeof value==='number'&&Number.isInteger(value)&&value>=1024&&value<=65535;
}
function validRevision(value:unknown):value is number {
  return typeof value==='number'&&Number.isSafeInteger(value)&&value>=1&&value<=1_000_000;
}
function summary(value:unknown,projectId:string):RevisionSummary{
  const row=exact(value,[
    'artifactRevisionId','parserName','projectId','projectRevision','version',
    'selectedParserPort','receiverProtocols','fileHashes','zipSha256',
    'createdAt','targetImportVerified','deploymentPerformed',
  ]);
  if(!SHA.test(String(row.artifactRevisionId))||!PARSER.test(String(row.parserName))||
    row.projectId!==projectId||!validRevision(row.projectRevision)||
    typeof row.version!=='string'||!VERSION.test(row.version)||
    !validPort(row.selectedParserPort)||!SHA.test(String(row.zipSha256))||
    row.targetImportVerified!==false||row.deploymentPerformed!==false||
    typeof row.createdAt!=='string'||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(row.createdAt)||
    !Number.isFinite(Date.parse(row.createdAt))||
    !Array.isArray(row.receiverProtocols)||row.receiverProtocols.length<1||
    row.receiverProtocols.length>2||
    row.receiverProtocols.some(p=>p!=='udp'&&p!=='tcp')||
    new Set(row.receiverProtocols).size!==row.receiverProtocols.length) {
    throw new Error('Unverified or foreign offline revision response.');
  }
  const hashes=exact(row.fileHashes,[row.parserName as string,(row.parserName as string)+'.conf']);
  if(Object.values(hashes).some(h=>typeof h!=='string'||!SHA.test(h)))
    throw new Error('Revision file hashes are invalid.');
  return row as unknown as RevisionSummary;
}
async function json(response:Response):Promise<unknown>{
  if(response.status!==200){
    if(response.status===403||response.status===401)
      throw new Error('Offline revision history access denied or unavailable (HTTP '+response.status+').');
    throw new Error('Offline revision request refused (HTTP '+response.status+').');
  }
  try{return await response.json();}catch{throw new Error('Invalid offline revision JSON response.');}
}
function post(action:string,body:unknown,requester:typeof fetch,accept='application/json'):Promise<Response>{
  return requester(BASE+action,{method:'POST',credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json',Accept:accept},body:JSON.stringify(body)});
}
export async function registerArtifactRevision(pair:GeneratedPair,version:string,
  expectedPort:number,requester:typeof fetch=fetch):Promise<RevisionSummary>{
  if(typeof version!=='string'||!VERSION.test(version)||!validPort(expectedPort))
    throw new Error('Invalid offline revision version or listener port.');
  const verified=await verifyGeneratedPair(pair);
  if(!pair.manifest.projectId||!PROJECT.test(pair.manifest.projectId))
    throw new Error('An exact parser project ID is required.');
  const payload=JSON.stringify({pair,version});
  if(new TextEncoder().encode(payload).byteLength>MAX_BYTES)
    throw new Error('Offline revision payload is too large.');
  const result=summary(await json(await post('register',{pair,version},requester)),
    pair.manifest.projectId);
  if(result.parserName!==verified.parserName||result.projectRevision!==verified.revision||
    result.version!==version||result.selectedParserPort!==expectedPort||
    Object.keys(result.fileHashes).some(name=>
      result.fileHashes[name]!==pair.manifest.fileHashes[name])) {
    throw new Error('The registered revision differs from the locally verified DRAFT.');
  }
  return result;
}
export async function listArtifactRevisions(projectId:string,
  requester:typeof fetch=fetch):Promise<RevisionSummary[]>{
  if(!PROJECT.test(projectId))throw new Error('A safe parser project ID is required.');
  const response=await requester(BASE+'list?projectId='+encodeURIComponent(projectId),{
    method:'GET',credentials:'same-origin',cache:'no-store',
    headers:{Accept:'application/json'}});
  const result=exact(await json(response),[
    'contract','revisions','persistent','deploymentPerformed',
  ]);
  if(result.contract!=='offline-revision-history.v0.1'||result.persistent!==false||
    result.deploymentPerformed!==false||!Array.isArray(result.revisions)||
    result.revisions.length>256)throw new Error('Offline history safety contract is unsupported.');
  const revisions=result.revisions.map(v=>summary(v,projectId));
  if(new Set(revisions.map(r=>r.artifactRevisionId)).size!==revisions.length)
    throw new Error('Duplicate immutable revision IDs from backend.');
  return revisions;
}
export async function compareArtifactRevisions(from:RevisionSummary,to:RevisionSummary,
  requester:typeof fetch=fetch):Promise<RevisionDiff>{
  if(from.projectId!==to.projectId||from.artifactRevisionId===to.artifactRevisionId)
    throw new Error('Comparison requires distinct revisions of the same project.');
  const result=exact(await json(await post('diff',{
    fromRevisionId:from.artifactRevisionId,toRevisionId:to.artifactRevisionId,
  },requester)),[
    'contract','fromRevisionId','toRevisionId','projectId','version',
    'selectedParserPort','files','realTargetVerified','appliesToDp',
  ]);
  if(result.contract!=='offline-artifact-diff.v0.1'||
    result.projectId!==from.projectId||
    result.fromRevisionId!==from.artifactRevisionId||
    result.toRevisionId!==to.artifactRevisionId||
    result.realTargetVerified!==false||result.appliesToDp!==false)
    throw new Error('Offline diff is not bound to the selected revisions.');
  const v=exact(result.version,['from','to','changed']);
  const p=exact(result.selectedParserPort,['from','to','changed']);
  if(v.from!==from.version||v.to!==to.version||
    v.changed!==(v.from!==v.to)||
    p.from!==from.selectedParserPort||p.to!==to.selectedParserPort||
    p.changed!==(p.from!==p.to)||!Array.isArray(result.files)||
    result.files.length!==2)throw new Error('Offline difference metadata failed verification.');
  const expectedNames=Object.keys(from.fileHashes).sort();
  if(expectedNames.join('|')!==Object.keys(to.fileHashes).sort().join('|'))
    throw new Error('Offline revision files are inconsistent.');
  const actualNames:string[]=[];
  for(const item of result.files){
    const f=exact(item,['name','fromSha256','toSha256','changed']);
    if(typeof f.name!=='string'||!expectedNames.includes(f.name)||
      f.fromSha256!==from.fileHashes[f.name]||
      f.toSha256!==to.fileHashes[f.name]||
      f.changed!==(f.fromSha256!==f.toSha256))
      throw new Error('Offline file hash difference failed verification.');
    actualNames.push(f.name);
  }
  if(new Set(actualNames).size!==2)throw new Error('Duplicated offline diff file.');
  return result as unknown as RevisionDiff;
}
async function sha256(bytes:ArrayBuffer):Promise<string>{
  if(!globalThis.crypto?.subtle)throw new Error('HTTPS WebCrypto is required for ZIP verification.');
  const hashed=await crypto.subtle.digest('SHA-256',bytes);
  return [...new Uint8Array(hashed)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
export async function retrieveRevisionZip(revision:RevisionSummary,
  current:RevisionSummary|null,requester:typeof fetch=fetch):Promise<VerifiedRevisionZip>{
  if(current&&(current.projectId!==revision.projectId||
    current.artifactRevisionId===revision.artifactRevisionId))
    throw new Error('Offline restore preview requires an older revision in the same project.');
  if(!SHA.test(revision.artifactRevisionId)||!SHA.test(revision.zipSha256)||
    !PARSER.test(revision.parserName)||!validRevision(revision.projectRevision))
    throw new Error('Invalid immutable revision download metadata.');
  const previewOnly=current!==null;
  const response=previewOnly
    ? await post('restore-preview',{previousRevisionId:revision.artifactRevisionId,
        expectedCurrentRevisionId:current.artifactRevisionId},requester,'application/zip')
    : await requester(BASE+'download?artifactRevisionId='+encodeURIComponent(revision.artifactRevisionId),{
        method:'GET',cache:'no-store',credentials:'same-origin',headers:{Accept:'application/zip'}});
  if(response.status!==200){
    if(response.status===403||response.status===401)
      throw new Error('Offline revision ZIP access denied or unavailable (HTTP '+response.status+').');
    throw new Error('Offline revision ZIP request refused (HTTP '+response.status+').');
  }
  const filename=revision.parserName+'-r'+revision.projectRevision+'.zip';
  const headers=response.headers;
  const length=headers.get('content-length');
  if(headers.get('content-type')!=='application/zip'||
    headers.get('content-disposition')!=='attachment; filename="'+filename+'"'||
    headers.get('x-parser-artifact-revision')!==revision.artifactRevisionId||
    headers.get('x-parser-zip-sha256')!==revision.zipSha256||
    (previewOnly&&headers.get('x-parser-restore-status')!=='OFFLINE_RESTORE_PREVIEW')||
    (!previewOnly&&headers.has('x-parser-restore-status'))||
    !length||!/^[1-9]\d*$/.test(length)||Number(length)>MAX_BYTES)
    throw new Error('Immutable ZIP metadata failed integrity checks.');
  const bytes=await response.arrayBuffer();
  const raw=new Uint8Array(bytes),end=raw.length-22;
  if(bytes.byteLength!==Number(length)||end<4||raw[0]!==0x50||raw[1]!==0x4b||
    raw[2]!==0x03||raw[3]!==0x04||
    raw[end]!==0x50||raw[end+1]!==0x4b||raw[end+2]!==0x05||raw[end+3]!==0x06||
    await sha256(bytes)!==revision.zipSha256)
    throw new Error('Offline ZIP SHA-256 or structure verification failed.');
  return {artifactRevisionId:revision.artifactRevisionId,filename,bytes,
    sha256:revision.zipSha256,previewOnly};
}
