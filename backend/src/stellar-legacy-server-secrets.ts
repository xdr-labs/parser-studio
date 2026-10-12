/**
 * Explicit backend-only POC profile loading and append-only local audit.
 * This module never chooses a credential path or contacts the POC by itself.
 * There is no automatic dev-atlas -> dev-drlink secret transfer.
 */
import {
  closeSync,constants,fstatSync,lstatSync,openSync,
  readFileSync,writeSync,
} from "node:fs";
import {basename,dirname,isAbsolute} from "node:path";
import {LegacyPocClient,type LegacyPocClientConfig,
  type LegacyAuditEvent} from "./stellar-legacy-client.js";
import {LegacyContractError,LEGACY_POC_CAPABILITIES} from "./stellar-legacy-plan.js";

function refuse(code:string):never{throw new LegacyContractError(code);}
const tenantPattern=/^[A-Za-z0-9_-]{1,128}$/;
function ownerUid():number{
  const uid=process.getuid?.();
  if(uid===undefined)refuse("POC_PLATFORM_UNSUPPORTED");
  return uid;
}
function checkParent(path:string):void{
  const parent=dirname(path);
  const stat=lstatSync(parent,{throwIfNoEntry:false});
  if(!stat||!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==ownerUid()||
    (stat.mode&0o077)!==0)refuse("POC_PRIVATE_DIRECTORY_UNSAFE");
}
function nofollow():number{
  if(typeof constants.O_NOFOLLOW!=="number")refuse("POC_NOFOLLOW_UNAVAILABLE");
  return constants.O_NOFOLLOW;
}

/** Returns only a client object with #private credentials; never returns key. */
export function loadPocProfileClient(
  absoluteProfilePath:string,
  injection:Pick<LegacyPocClientConfig,
    "fetchImpl"|"clock"|"approveWrite"|"audit">={}
):LegacyPocClient{
  if(typeof absoluteProfilePath!=="string"||!isAbsolute(absoluteProfilePath))
    refuse("POC_PRIVATE_PATH_INVALID");
  checkParent(absoluteProfilePath);
  const entry=lstatSync(absoluteProfilePath,{throwIfNoEntry:false});
  if(!entry||!entry.isFile()||entry.isSymbolicLink()||entry.uid!==ownerUid()||
    entry.nlink!==1||(entry.mode&0o077)!==0||
    entry.size<=0||entry.size>16384)refuse("POC_PRIVATE_FILE_UNSAFE");
  const fd=openSync(absoluteProfilePath,constants.O_RDONLY|nofollow());
  let content="";
  try{
    const open=fstatSync(fd);
    if(!open.isFile()||open.uid!==ownerUid()||open.nlink!==1||
      (open.mode&0o077)!==0||open.size>16384)
      refuse("POC_PRIVATE_FILE_UNSAFE");
    content=new TextDecoder("utf-8",{fatal:true}).decode(readFileSync(fd));
  }catch{
    refuse("POC_PRIVATE_FILE_UNSAFE");
  }finally{closeSync(fd);}
  let data:unknown;
  try{data=JSON.parse(content);}catch{refuse("POC_PRIVATE_PROFILE_INVALID");}
  if(!data||typeof data!=="object"||Array.isArray(data))
    refuse("POC_PRIVATE_PROFILE_INVALID");
  const object=data as Record<string,unknown>;
  if(Object.keys(object).sort().join(",")!=="host,key,tenant" ||
    object.host!==LEGACY_POC_CAPABILITIES.allowedHost ||
    typeof object.tenant!=="string"||!tenantPattern.test(object.tenant)||
    typeof object.key!=="string"||!object.key||object.key.length>8192)
    refuse("POC_PRIVATE_PROFILE_INVALID");
  return new LegacyPocClient({host:object.host as string,tenant:object.tenant as string,
    apiKey:object.key as string,...injection});
}

/** A durable, non-sensitive before/after mutation event; operator provides
 * the private owner-controlled 0700 directory, NOT the browser.
 */
export function createPocFileAuditSink(absoluteAuditPath:string){
  if(typeof absoluteAuditPath!=="string"||!isAbsolute(absoluteAuditPath)||
    !/^[A-Za-z0-9_.-]{1,80}\.ndjson$/.test(basename(absoluteAuditPath)))
    refuse("POC_AUDIT_PATH_INVALID");
  checkParent(absoluteAuditPath);
  return async(event:LegacyAuditEvent):Promise<void>=>{
    if(!["BEFORE","AFTER","FAILED","CLEANUP"].includes(event.phase)||
      !["POST","PUT","DELETE","CLEANUP"].includes(event.method)||
      !tenantPattern.test(event.tenant)||
      !/^customized_ps_api_crud_test_[0-9a-f]{6,16}$/.test(event.name)||
      !/^[A-Za-z0-9_.-]{3,96}$/.test(event.approvalId)||
      typeof event.version!=="string"||event.version.length>64||
      event.runtimeParsingVerified!==false||event.targetImportVerified!==false)
      refuse("POC_AUDIT_EVENT_INVALID");
    checkParent(absoluteAuditPath);
    const old=lstatSync(absoluteAuditPath,{throwIfNoEntry:false});
    if(old&&(!old.isFile()||old.isSymbolicLink()||old.nlink!==1||
      old.uid!==ownerUid()||(old.mode&0o077)!==0))
      refuse("POC_AUDIT_FILE_UNSAFE");
    const fd=openSync(absoluteAuditPath,
      constants.O_WRONLY|constants.O_CREAT|constants.O_APPEND|nofollow(),0o600);
    try{
      const st=fstatSync(fd);
      if(!st.isFile()||st.uid!==ownerUid()||st.nlink!==1||
        (st.mode&0o077)!==0)refuse("POC_AUDIT_FILE_UNSAFE");
      // Author exclusively owns this file. We only serialize known primitives,
      // never caller-supplied source, headers, JWT, API Key or vendor bodies.
      const safe={
        kind:"parser-studio.legacy-test-audit.v0.1",
        time:new Date().toISOString(),
        phase:event.phase,method:event.method,
        tenant:event.tenant,name:event.name,version:event.version,
        approvalId:event.approvalId,
        apiRegistrationVerified:event.apiRegistrationVerified===true,
        runtimeParsingVerified:false,targetImportVerified:false,
        ...(Number.isInteger(event.httpStatus)?{httpStatus:event.httpStatus}:{}),
      };
      writeSync(fd,JSON.stringify(safe)+"\n");
    }finally{closeSync(fd);}
  };
}
