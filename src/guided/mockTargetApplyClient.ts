/** Strictly MOCK_ONLY backend contract. No real DP URL, API key or packets. */
import type {RevisionSummary} from './artifactRevisionClient';

const BASE='/api/v1/parser-pairs/target/apply';
const SHA=/^[0-9a-f]{64}$/;
const NAME=/^customized_[a-z][a-z0-9_]{1,47}$/;
const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const APPROVAL=/^[A-Za-z0-9._-]{8,96}$/;
const STATUSES=new Set(['NOT_ATTEMPTED','IN_PROGRESS','MOCK_READBACK_VERIFIED','DENIED','UNVERIFIED']);
export type MockApplyStatus='NOT_ATTEMPTED'|'IN_PROGRESS'|'MOCK_READBACK_VERIFIED'|'DENIED'|'UNVERIFIED';
export type MockApplyStatusResult={
  artifactRevisionId:string;mode:'MOCK_ONLY';status:MockApplyStatus;
  ephemeral:true;realTargetVerified:false;
};
export type MockApplyProof={
  artifactRevisionId:string;mode:'MOCK_ONLY';status:'MOCK_READBACK_VERIFIED';
  name:string;version:string;selectedParserPort:number;
  realTargetVerified:false;
};
function object(input:unknown):Record<string,unknown>{
  if(!input||typeof input!=='object'||Array.isArray(input)||
    Object.getPrototypeOf(input)!==Object.prototype)
    throw new Error('Invalid mock-only Apply contract.');
  return input as Record<string,unknown>;
}
function exact(input:unknown,keys:string[]):Record<string,unknown>{
  const value=object(input);
  if(Object.keys(value).sort().join('|')!==[...keys].sort().join('|'))
    throw new Error('Unsafe or unrecognized mock-only Apply response.');
  return value;
}
function revisionCheck(revision:RevisionSummary):void{
  if(!revision||!SHA.test(revision.artifactRevisionId)||!NAME.test(revision.parserName)||
    !VERSION.test(revision.version)||!Number.isSafeInteger(revision.projectRevision)||
    revision.selectedParserPort<1024||revision.selectedParserPort>65535||
    revision.targetImportVerified!==false||revision.deploymentPerformed!==false)
    throw new Error('Mock Apply requires a verified immutable DRAFT revision.');
  const hashes=exact(revision.fileHashes,[revision.parserName,revision.parserName+'.conf']);
  if(Object.values(hashes).some(v=>typeof v!=='string'||!SHA.test(v)))
    throw new Error('Mock Apply requires verified file hashes.');
}
async function read(response:Response):Promise<unknown>{
  if(response.status!==200){
    if(response.status===401||response.status===403)
      throw new Error('Mock Apply access denied or unavailable (HTTP '+response.status+').');
    throw new Error('Mock Apply rejected (HTTP '+response.status+').');
  }
  try{return await response.json();}
  catch{throw new Error('Invalid mock-only Apply JSON response.');}
}
export async function getMockApplyStatus(revision:RevisionSummary,
  requester:typeof fetch=fetch):Promise<MockApplyStatusResult>{
  revisionCheck(revision);
  const response=await requester(BASE+'/status?artifactRevisionId='+encodeURIComponent(revision.artifactRevisionId),{
    method:'GET',credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
  const data=exact(await read(response),[
    'contract','mode','artifactRevisionId','status','ephemeral','realTargetVerified',
    'sensorReadyVerified','targetImportVerified','realRuntimeParsingVerified',
  ]);
  if(data.contract!=='target-apply-mock.v0.1'||data.mode!=='MOCK_ONLY'||
    data.artifactRevisionId!==revision.artifactRevisionId||
    !STATUSES.has(String(data.status))||data.ephemeral!==true||
    data.realTargetVerified!==false||data.sensorReadyVerified!==false||
    data.targetImportVerified!==false||data.realRuntimeParsingVerified!==false)
    throw new Error('Mock Apply status is not a safe offline-only response.');
  return {artifactRevisionId:revision.artifactRevisionId,
    mode:'MOCK_ONLY',status:data.status as MockApplyStatus,
    ephemeral:true,realTargetVerified:false};
}
export async function submitMockApply(revision:RevisionSummary,approvalId:string,
  acknowledged:boolean,requester:typeof fetch=fetch):Promise<MockApplyProof>{
  revisionCheck(revision);
  if(!acknowledged||typeof approvalId!=='string'||!APPROVAL.test(approvalId))
    throw new Error('Explicit mock-only confirmation and operator approval ID are required.');
  const response=await requester(BASE,{method:'POST',credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json',Accept:'application/json'},
    body:JSON.stringify({artifactRevisionId:revision.artifactRevisionId,
      expectedName:revision.parserName,expectedVersion:revision.version,
      approvalId,confirmed:true})});
  const data=exact(await read(response),[
    'artifactRevisionId','fileHashes','name','tenant','origin','version',
    'selectedParserPort','registration','mode','status','realTargetVerified',
  ]);
  let hostname='';
  try{
    const url=new URL(data.origin as string);
    if(url.protocol==='https:'&&!url.username&&!url.password&&
      (url.pathname==='/'||url.pathname==='')&&!url.search&&!url.hash)
      hostname=url.hostname;
  }catch{/* No raw target hostname is shown. */}
  const hashes=exact(data.fileHashes,[revision.parserName,revision.parserName+'.conf']);
  const info=exact(data.registration,[
    'status','apiReadbackVerified','realRuntimeParsingVerified','sensorReadyVerified',
    'targetImportVerified',
  ]);
  if(!hostname.endsWith('.invalid')||!data.tenant||typeof data.tenant!=='string'||
    data.artifactRevisionId!==revision.artifactRevisionId||
    data.name!==revision.parserName||data.version!==revision.version||
    data.selectedParserPort!==revision.selectedParserPort||
    Object.keys(hashes).some(k=>hashes[k]!==revision.fileHashes[k])||
    data.mode!=='MOCK_ONLY'||data.status!=='MOCK_READBACK_VERIFIED'||
    data.realTargetVerified!==false||
    info.status!=='API_REGISTERED_READBACK'||info.apiReadbackVerified!==true||
    info.realRuntimeParsingVerified!==false||info.sensorReadyVerified!==false||
    info.targetImportVerified!==false)
    throw new Error('Mock Apply proof failed integrity or offline-only validation.');
  return {artifactRevisionId:revision.artifactRevisionId,mode:'MOCK_ONLY',
    status:'MOCK_READBACK_VERIFIED',name:revision.parserName,
    version:revision.version,selectedParserPort:revision.selectedParserPort,
    realTargetVerified:false};
}
