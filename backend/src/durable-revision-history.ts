/**
 * Opt-in, offline-only single-writer durable revision and mock-Apply audit store.
 * Caller MUST provision a private owner-only directory and trusted authentication.
 * This never loads target credentials, opens sockets, activates a parser or sends logs.
 *
 * Whole-file SHA-256 and recompiled pair hashes detect accidental tampering. They
 * do NOT authenticate against an attacker who can rewrite this owner's private file.
 * Each mutation holds an exclusive per-directory lock and uses fsync + atomic rename.
 * A crash can leave a lock, which requires explicit operator reconciliation.
 */
import {createHash,randomBytes} from "node:crypto";
import {
  closeSync,constants,existsSync,fsyncSync,fstatSync,lstatSync,openSync,
  readFileSync,realpathSync,renameSync,unlinkSync,writeSync
} from "node:fs";
import {basename,dirname,isAbsolute,join} from "node:path";
import {TextDecoder} from "node:util";
import {buildArtifactPackage} from "./artifact-package.js";
import {ArtifactRevisionHistory,ArtifactRevisionHistoryError,
  type ArtifactRevisionHistoryOptions,type ArtifactRevisionSummary,
  type ArtifactRevisionDownload,type ArtifactRevisionDiff,type OfflineRestorePreview,
  type RevisionOwner,type ServerOwnedArtifactRevision} from "./artifact-revision-history.js";
import type {PairExport} from "./types.js";
import type {TargetApplyAuditEvent} from "./target-apply-bff.js";

const SCHEMA="parser-studio.offline-revisions.v0.1" as const;
const MAX_BYTES=16*1024*1024;
const MAX_AUDITS=256;
const SHA=/^[0-9a-f]{64}$/;
const ACTOR=/^[A-Za-z0-9_.:@-]{1,128}$/;
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const sha=(text:string)=>createHash("sha256").update(text,"utf8").digest("hex");
const deny=(code:string):never=>{throw new ArtifactRevisionHistoryError(code);};
type Row={ownerId:string;tenant:string;createdAt:number;version:string;
  artifactRevisionId:string;zipSha256:string;pair:PairExport};
export type OfflineMockAudit={actorId:string;tenant:string;
  phase:"BEFORE"|"AFTER";status:"REQUESTED"|"MOCK_READBACK_VERIFIED"|"DENIED"|"UNVERIFIED";
  artifactRevisionId:string;at:number};
type Unsigned={schema:typeof SCHEMA;generation:number;records:Row[];
  audits:OfflineMockAudit[]};
type Snapshot=Unsigned&{checksum:string};
const empty=():Unsigned=>({schema:SCHEMA,generation:0,records:[],audits:[]});
const exact=(value:unknown,keys:string[]):value is Record<string,unknown>=>{
  return value!==null&&typeof value==="object"&&!Array.isArray(value)&&
    Object.keys(value).sort().join(",")===keys.slice().sort().join(",");
};
const rowKeys=["ownerId","tenant","createdAt","version","artifactRevisionId","zipSha256","pair"];
// Only compiler-owned fixed warnings may enter durable storage; caller-controlled
// warning strings must never become a covert raw-log/credential persistence path.
// Already stored historical fixed compiler warnings remain readable; neither
// variant accepts free-form customer warning strings or runtime-supplied fields.
const PREVIOUS_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Supported bounded subset: JSON, KV, CSV, RFC5424, standalone CEF/LEEF; non-JSON physical multiline is unsupported, with typed mapping, limited routing and UDP/TCP.",
  "No production deployment or live sensor installation has occurred.",
];
// Historical static compiler-warning profiles remain safe to read verbatim.
const RFC3164_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Supported bounded subset: JSON, KV, CSV, RFC3164/RFC5424 with explicit body, standalone CEF/LEEF; RFC3164 time lacks year/zone; mixed and non-JSON physical multiline remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Supported bounded subset: JSON/KV/CSV, RFC3164/RFC5424 explicit body, CEF/LEEF and allowlisted mixed JSON/KV/CEF/LEEF; mixed Syslog and multiline remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
// Exact compiler-owned warning set for explicit TCP blank-line JSON frames.
const JAVA_LF_LF_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Only explicitly TCP LF LF framed bounded Java exception stack traces are supported; arbitrary Java formats, UDP and unframed multiline remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const REVIEWED_MIXED_CSV_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Mixed CSV columns and delimiter require explicit user review. Unrecognized rows are not auto-routed and arbitrary schemas remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const RFC3164_CEF_LEEF_MIXED_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Strict RFC3164 CEF/LEEF mixed requires explicit allowlist; year and timezone remain unknown and all unreviewed bodies and multiline remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const RFC5424_JSON_KV_MIXED_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Strict RFC5424-wrapped JSON/KV in mixed parsers requires an explicit allowlist; unreviewed Syslog bodies, CSV and multiline remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const RFC3164_MIXED_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Only explicitly allowlisted RFC3164 TAG KV mixed events are supported; header year and timezone remain unknown; other mixed Syslog, CSV and unframed multiline remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const RFC5424_MIXED_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Only explicitly allowlisted RFC5424-wrapped CEF/LEEF mixed events are supported; RFC3164 mixing, arbitrary Syslog/CSV mixing and unframed multiline remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const BLANKLINE_JSON_REVIEWED_WARNINGS=[
  "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
  "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
  "Only explicitly TCP blank-line-framed JSON is supported for multiline input; general multiline and mixed Syslog remain unsupported.",
  "No production deployment or live sensor installation has occurred.",
];
const auditKeys=["actorId","tenant","phase","status","artifactRevisionId","at"];
const validActor=(actor:RevisionOwner):boolean=>
  !!actor&&typeof actor.ownerId==="string"&&ACTOR.test(actor.ownerId)&&
  typeof actor.tenant==="string"&&TENANT.test(actor.tenant);
const ownedKey=(a:RevisionOwner,id:string)=>a.tenant+"|"+a.ownerId+"|"+id;
function safePair(value:unknown):value is PairExport{
  if(!exact(value,["contract","files","manifest"])||
     !Array.isArray(value.files)||value.files.length!==2||
     !value.files.every(f=>exact(f,["name","content","sha256","bytes"]))||
     !exact(value.manifest,["status","contract","projectId","projectRevision",
       "fileHashes","schemaRevision","engineVerified","targetImportVerified","warnings"])||
     !Array.isArray(value.manifest.warnings)||
     ![REVIEWED_WARNINGS,REVIEWED_MIXED_CSV_WARNINGS,JAVA_LF_LF_REVIEWED_WARNINGS,RFC3164_CEF_LEEF_MIXED_REVIEWED_WARNINGS,RFC5424_JSON_KV_MIXED_REVIEWED_WARNINGS,RFC3164_MIXED_REVIEWED_WARNINGS,RFC5424_MIXED_REVIEWED_WARNINGS,BLANKLINE_JSON_REVIEWED_WARNINGS,RFC3164_REVIEWED_WARNINGS,PREVIOUS_REVIEWED_WARNINGS].some(known=>
       JSON.stringify((value.manifest as {warnings:unknown}).warnings)===JSON.stringify(known)))
    return false;
  return true;
}
function auditInput(v:unknown):asserts v is TargetApplyAuditEvent{
  if(!exact(v,["actorId","tenant","phase","status","artifactRevisionId"])||
     typeof v.actorId!=="string"||!ACTOR.test(v.actorId)||
     typeof v.tenant!=="string"||!TENANT.test(v.tenant)||
     typeof v.artifactRevisionId!=="string"||!SHA.test(v.artifactRevisionId)||
     !((v.phase==="BEFORE"&&v.status==="REQUESTED")||
       (v.phase==="AFTER"&&["MOCK_READBACK_VERIFIED","DENIED","UNVERIFIED"].includes(v.status as string))))
    deny("AUDIT_EVENT_INVALID");
}
function auditSequence(events:OfflineMockAudit[]):void{
  const opened=new Set<string>();
  for(const row of events){
    if(!exact(row,auditKeys)||!Number.isSafeInteger(row.at)||row.at<0)
      deny("REVISION_STORE_INTEGRITY");
    try{
      auditInput({actorId:row.actorId,tenant:row.tenant,phase:row.phase,
        status:row.status,artifactRevisionId:row.artifactRevisionId});
    }catch{deny("REVISION_STORE_INTEGRITY");}
    const key=ownedKey({ownerId:row.actorId,tenant:row.tenant},row.artifactRevisionId);
    if(row.phase==="BEFORE"){
      if(opened.has(key))deny("REVISION_STORE_INTEGRITY");
      opened.add(key);
    }else{
      if(!opened.delete(key))deny("REVISION_STORE_INTEGRITY");
    }
  }
}
export class DurableArtifactRevisionHistory extends ArtifactRevisionHistory{
  readonly #path:string;
  readonly #lockPath:string;
  readonly #now:()=>number;
  readonly #ttl:number;
  readonly #max:number;
  #seen=false;
  override get persistent():boolean{return true;}
  constructor(file:string,options:ArtifactRevisionHistoryOptions={}){
    super(options);
    if(typeof file!=="string"||!isAbsolute(file)||
       basename(file)!=="artifact-revisions.json"||file.includes("/../")||
       file.includes("/./"))deny("REVISION_PATH_INVALID");
    this.#path=file;
    this.#lockPath=join(dirname(file),".artifact-revisions.lock");
    this.#now=options.now??Date.now;
    this.#ttl=options.ttlMs??86400000;
    this.#max=options.maxRevisions??128;
  }
  #time():number{
    const ms=this.#now();
    if(!Number.isSafeInteger(ms)||ms<0)deny("REVISION_CLOCK_INVALID");
    return ms;
  }
  #parent():void{
    const dir=dirname(this.#path);
    const uid=process.getuid?.();
    if(uid===undefined)deny("REVISION_PLATFORM_UNSUPPORTED");
    let st;
    try{st=lstatSync(dir);}catch{deny("REVISION_DIRECTORY_UNSAFE");}
    if(!st||!st.isDirectory()||st.isSymbolicLink()||st.uid!==uid||
       (st.mode&0o077)!==0)deny("REVISION_DIRECTORY_UNSAFE");
    try{if(realpathSync(dir)!==dir)deny("REVISION_DIRECTORY_UNSAFE");}
    catch{deny("REVISION_DIRECTORY_UNSAFE");}
    if(typeof constants.O_NOFOLLOW!=="number")deny("REVISION_NOFOLLOW_UNAVAILABLE");
  }
  #statFile():boolean{
    this.#parent();
    const st=lstatSync(this.#path,{throwIfNoEntry:false});
    if(!st){
      if(this.#seen)deny("REVISION_FILE_UNSAFE");
      return false;
    }
    if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||
       st.uid!==process.getuid?.()||(st.mode&0o077)!==0||
       st.size<1||st.size>MAX_BYTES)deny("REVISION_FILE_UNSAFE");
    return true;
  }
  #read():Unsigned{
    if(!this.#statFile())return empty();
    let fd=-1;
    try{
      fd=openSync(this.#path,constants.O_RDONLY|constants.O_NOFOLLOW);
      const st=fstatSync(fd);
      const pathSt=lstatSync(this.#path);
      if(!st.isFile()||st.nlink!==1||st.uid!==process.getuid?.()||
         (st.mode&0o077)!==0||st.size<1||st.size>MAX_BYTES||
         st.dev!==pathSt.dev||st.ino!==pathSt.ino)deny("REVISION_FILE_UNSAFE");
      const bytes=readFileSync(fd);
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const parsed:unknown=JSON.parse(raw);
      if(!exact(parsed,["schema","generation","records","audits","checksum"])||
         parsed.schema!==SCHEMA||!Number.isSafeInteger(parsed.generation)||
         (parsed.generation as number)<1||
         !Array.isArray(parsed.records)||!Array.isArray(parsed.audits)||
         parsed.records.length>this.#max||parsed.audits.length>MAX_AUDITS||
         typeof parsed.checksum!=="string"||!SHA.test(parsed.checksum)){
        deny("REVISION_STORE_INTEGRITY");
      }
      const {checksum,...unsigned}=parsed as unknown as Snapshot;
      if(checksum!==sha(JSON.stringify(unsigned)))deny("REVISION_STORE_INTEGRITY");
      this.#validate(unsigned);
      this.#seen=true;
      return unsigned;
    }catch(err){
      if(err instanceof ArtifactRevisionHistoryError)throw err;
      return deny("REVISION_STORE_INTEGRITY");
    }finally{if(fd>=0)closeSync(fd);}
  }
  #validate(snapshot:Unsigned):void{
    const now=this.#time();
    const seen=new Set<string>();
    let prior=-1;
    for(const row of snapshot.records){
      if(!exact(row,rowKeys)||!validActor({ownerId:row.ownerId,tenant:row.tenant})||
         typeof row.version!=="string"||!VERSION.test(row.version)||
         !Number.isSafeInteger(row.createdAt)||row.createdAt<0||
         row.createdAt<prior||row.createdAt>now||
         typeof row.artifactRevisionId!=="string"||!SHA.test(row.artifactRevisionId)||
         typeof row.zipSha256!=="string"||!SHA.test(row.zipSha256)||
         !safePair(row.pair))deny("REVISION_STORE_INTEGRITY");
      const key=ownedKey({ownerId:row.ownerId,tenant:row.tenant},row.artifactRevisionId);
      if(seen.has(key))deny("REVISION_STORE_INTEGRITY");
      seen.add(key);prior=row.createdAt;
      try{
        const package_=buildArtifactPackage(row.pair,row.version);
        if(package_.manifest.artifactRevisionId!==row.artifactRevisionId||
           package_.zipSha256!==row.zipSha256)deny("REVISION_STORE_INTEGRITY");
      }catch{deny("REVISION_STORE_INTEGRITY");}
    }
    if(snapshot.audits.some(a=>a.at>now))deny("REVISION_STORE_INTEGRITY");
    auditSequence(snapshot.audits);
    if(snapshot.audits.some(a=>!seen.has(ownedKey(
      {ownerId:a.actorId,tenant:a.tenant},a.artifactRevisionId))))
      deny("REVISION_STORE_INTEGRITY");
  }
  #active(snapshot:Unsigned,now:number):Row[]{
    return snapshot.records.filter(r=>now-r.createdAt<this.#ttl);
  }
  #replay(snapshot:Unsigned):ArtifactRevisionHistory{
    let at=0;
    const history=new ArtifactRevisionHistory({
      now:()=>at,ttlMs:this.#ttl,maxRevisions:this.#max});
    try{
      for(const row of snapshot.records){
        at=row.createdAt;
        const registered=history.register({ownerId:row.ownerId,tenant:row.tenant},
          row.pair,row.version);
        if(registered.artifactRevisionId!==row.artifactRevisionId||
           registered.zipSha256!==row.zipSha256)
          deny("REVISION_STORE_INTEGRITY");
      }
      at=this.#time();
      // Force TTL expiration even on a read-only operation.
      return history;
    }catch{return deny("REVISION_STORE_INTEGRITY");}
  }
  #lock<T>(fn:()=>T):T{
    this.#parent();
    let fd=-1;
    try{
      fd=openSync(this.#lockPath,constants.O_CREAT|constants.O_EXCL|
        constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
    }catch{return deny("REVISION_STORE_LOCKED");}
    try{
      const st=fstatSync(fd);
      if(!st.isFile()||st.uid!==process.getuid?.()||st.nlink!==1||
         (st.mode&0o077)!==0)deny("REVISION_STORE_LOCKED");
      return fn();
    }finally{
      closeSync(fd);
      // Private directory, single trusted process writer.
      unlinkSync(this.#lockPath);
    }
  }
  #write(next:Unsigned):void{
    this.#parent();
    this.#statFile();
    this.#validate(next);
    const bytes=Buffer.from(JSON.stringify({...next,checksum:sha(JSON.stringify(next))}),"utf8");
    if(bytes.length>MAX_BYTES)deny("REVISION_CAPACITY_REACHED");
    const stage=join(dirname(this.#path),".revisions-"+randomBytes(12).toString("hex")+".tmp");
    let fd=-1;
    try{
      fd=openSync(stage,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
        constants.O_NOFOLLOW,0o600);
      const st=fstatSync(fd);
      if(!st.isFile()||st.uid!==process.getuid?.()||(st.mode&0o077)!==0||
         st.nlink!==1)deny("REVISION_FILE_UNSAFE");
      if(writeSync(fd,bytes)!==bytes.length)deny("REVISION_STORE_IO_ERROR");
      fsyncSync(fd);
      closeSync(fd);fd=-1;
      this.#statFile();
      renameSync(stage,this.#path);
      this.#seen=true;
      const dirFd=openSync(dirname(this.#path),constants.O_RDONLY);
      try{fsyncSync(dirFd);}finally{closeSync(dirFd);}
    }catch(error){
      if(error instanceof ArtifactRevisionHistoryError)throw error;
      return deny("REVISION_STORE_IO_ERROR");
    }finally{
      if(fd>=0)closeSync(fd);
      if(existsSync(stage))unlinkSync(stage);
    }
  }
  override register(actor:RevisionOwner,pair:PairExport,version:string):ArtifactRevisionSummary{
    if(!validActor(actor))deny("REVISION_ACTOR_INVALID");
    return this.#lock(()=>{
      const state=this.#read();
      const now=this.#time();
      const rows=this.#active(state,now);
      const h=this.#replay(state);
      // A stale project revision cannot overwrite a more recent immutable pair.
      const candidate=buildArtifactPackage(pair,version);
      const project=candidate.manifest.projectId;
      const existing=h.list(actor,project);
      if(existing.some(r=>r.artifactRevisionId===candidate.manifest.artifactRevisionId))
        deny("REVISION_DUPLICATE");
      if(existing.some(r=>r.projectRevision>=candidate.manifest.projectRevision))
        deny("REVISION_VERSION_CONFLICT");
      if(rows.length>=this.#max)deny("REVISION_CAPACITY_REACHED");
      const saved=h.register(actor,pair,version);
      // Only these reviewed pair fields can enter the artifact store.
      if(!safePair(pair))deny("REVISION_STORE_INPUT_UNSAFE");
      const normalized=structuredClone(pair);
      const next:Unsigned={schema:SCHEMA,generation:state.generation+1,
        records:[...rows,{ownerId:actor.ownerId,tenant:actor.tenant,createdAt:now,
          version,artifactRevisionId:saved.artifactRevisionId,
          zipSha256:saved.zipSha256,pair:normalized}],
        audits:state.audits.filter(a=>rows.some(r=>ownedKey(
          {ownerId:r.ownerId,tenant:r.tenant},r.artifactRevisionId)===
          ownedKey({ownerId:a.actorId,tenant:a.tenant},a.artifactRevisionId)))};
      this.#write(next);
      return saved;
    });
  }
  #access<T>(fn:(h:ArtifactRevisionHistory)=>T):T{
    return fn(this.#replay(this.#read()));
  }
  override list(actor:RevisionOwner,projectId:string):ArtifactRevisionSummary[]{
    return this.#access(h=>h.list(actor,projectId));
  }
  override download(actor:RevisionOwner,id:string):ArtifactRevisionDownload{
    return this.#access(h=>h.download(actor,id));
  }
  override diff(actor:RevisionOwner,from:string,to:string):ArtifactRevisionDiff{
    return this.#access(h=>h.diff(actor,from,to));
  }
  override prepareRestore(actor:RevisionOwner,oldId:string,currentId:string):OfflineRestorePreview{
    return this.#access(h=>h.prepareRestore(actor,oldId,currentId));
  }
  override resolveOwnedRevision(actor:RevisionOwner,id:string):ServerOwnedArtifactRevision{
    return this.#access(h=>h.resolveOwnedRevision(actor,id));
  }
  /** Inject as the MOCK_ONLY gateway's audit callback; never accepts raw data. */
  recordMockApplyAudit(input:TargetApplyAuditEvent):void{
    auditInput(input);
    this.#lock(()=>{
      const state=this.#read();
      const now=this.#time();
      const h=this.#replay(state);
      h.resolveOwnedRevision({ownerId:input.actorId,tenant:input.tenant},
        input.artifactRevisionId);
      if(state.audits.length>=MAX_AUDITS)deny("REVISION_AUDIT_CAPACITY");
      const nextEvent={...input,at:now};
      const audits=[...state.audits,nextEvent];
      try{auditSequence(audits);}catch{deny("AUDIT_TRANSITION_INVALID");}
      this.#write({...state,generation:state.generation+1,audits});
    });
  }
  listMockApplyAudit(actor:RevisionOwner):OfflineMockAudit[]{
    if(!validActor(actor))deny("REVISION_ACTOR_INVALID");
    const state=this.#read();
    return state.audits.filter(a=>a.actorId===actor.ownerId&&a.tenant===actor.tenant)
      .map(a=>({...a}));
  }
}
