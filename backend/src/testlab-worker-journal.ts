/**
 * Fail-closed, owner-only metadata journal for a future approved in-network
 * Test Lab worker. It contains NO source log, destination, key or JWT.
 *
 * On process restart, RUNNING/PAUSED journals are *never* auto-resumed:
 * the original sample/delivery sink/approval is intentionally unavailable,
 * and an operator must stop/reconcile and approve a completely new run.
 *
 * Single authorized process writer only. Hash linking detects accidental
 * corruption; it is not signed authentication against a hostile file owner.
 */
import {createHash} from "node:crypto";
import {
  closeSync,constants,fsyncSync,fstatSync,lstatSync,openSync,
  readFileSync,writeSync,
} from "node:fs";
import {dirname,isAbsolute} from "node:path";

export type WorkerLifecycle="RUNNING"|"PAUSED"|"STOPPED"|"EXPIRED"|"FAILED"|"COMPLETED";
export type WorkerMetadata={
  runId:string;
  actorId:string;
  state:WorkerLifecycle;
  leaseExpiresAt:string;
  sentCount:number;
  maxEvents:number;
  artifactRevisionId:string;
  replayMode:"single"|"constant-rate"|"original-gaps";
  sampleFamilyCount:number;
};
type JournalRecord=WorkerMetadata&{
  schema:"parser-studio.worker-ledger.v0.1";
  sequence:number;
  at:string;
  previousHash:string;
  hash:string;
};
export type WorkerReconciliation={
  runId:string;
  state:"REAPPROVAL_REQUIRED"|"EXPIRED_NO_RESTART";
  lastKnownSentCount:number;
  autoResumeAllowed:false;
  originalSourceRestored:false;
  sensorIngestVerified:false;
};
export class WorkerJournalError extends Error{
  constructor(readonly code:string){super(code);this.name="WorkerJournalError";}
}
const bad=(code:string):never=>{throw new WorkerJournalError(code);};
const ID=/^test_run_[0-9a-f]{32}$/;
const ACTOR=/^[A-Za-z0-9_.:@-]{1,128}$/;
const SHA=/^[0-9a-f]{64}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const SCHEMA="parser-studio.worker-ledger.v0.1" as const;
const MAX_LEDGER=1024*1024;
const GENESIS="0".repeat(64);
const closed=new Set<WorkerLifecycle>(["STOPPED","EXPIRED","FAILED","COMPLETED"]);
const KEYS=["runId","actorId","state","leaseExpiresAt","sentCount","maxEvents",
  "artifactRevisionId","replayMode","sampleFamilyCount"];
const RECORD_KEYS=new Set([...KEYS,"schema","sequence","at","previousHash","hash"]);
const sha256=(value:string)=>createHash("sha256").update(value,"utf8").digest("hex");
function isPlain(value:unknown):value is Record<string,unknown>{
  return value!==null&&typeof value==="object"&&!Array.isArray(value);
}
function metadata(value:unknown):asserts value is WorkerMetadata{
  if(!isPlain(value)||Object.keys(value).sort().join(",")!==[...KEYS].sort().join(",")||
    typeof value.runId!=="string"||!ID.test(value.runId)||
    typeof value.actorId!=="string"||!ACTOR.test(value.actorId)||
    !["RUNNING","PAUSED","STOPPED","EXPIRED","FAILED","COMPLETED"].includes(
      value.state as string)||
    typeof value.leaseExpiresAt!=="string"||!TIME.test(value.leaseExpiresAt)||
    !Number.isFinite(Date.parse(value.leaseExpiresAt))||
    !Number.isSafeInteger(value.sentCount)||(value.sentCount as number)<0||
    !Number.isSafeInteger(value.maxEvents)||(value.maxEvents as number)<1||
    (value.maxEvents as number)>300000||
    (value.sentCount as number)>(value.maxEvents as number)||
    typeof value.artifactRevisionId!=="string"||!SHA.test(value.artifactRevisionId)||
    !["single","constant-rate","original-gaps"].includes(value.replayMode as string)||
    !Number.isInteger(value.sampleFamilyCount)||
    (value.sampleFamilyCount as number)<1||
    (value.sampleFamilyCount as number)>12)
    bad("WORKER_EVENT_INVALID");
}
function normalize(input:WorkerMetadata):WorkerMetadata{
  metadata(input);
  return {
    runId:input.runId,actorId:input.actorId,
    state:input.state,leaseExpiresAt:input.leaseExpiresAt,
    sentCount:input.sentCount,maxEvents:input.maxEvents,
    artifactRevisionId:input.artifactRevisionId,
    replayMode:input.replayMode,sampleFamilyCount:input.sampleFamilyCount,
  };
}
function hashFor(entry:Omit<JournalRecord,"hash">):string{
  return sha256(entry.previousHash+"\n"+JSON.stringify(entry));
}

export class TestLabWorkerJournal{
  readonly #path:string;
  #written=false;
  constructor(absolutePath:string){
    if(typeof absolutePath!=="string"||!isAbsolute(absolutePath)||
      !/\/run-journal\.ndjson$/.test(absolutePath))bad("WORKER_PATH_INVALID");
    this.#path=absolutePath;
  }
  #parent():void{
    const path=dirname(this.#path),info=lstatSync(path,{throwIfNoEntry:false});
    const uid=process.getuid?.();
    if(uid===undefined)bad("WORKER_PLATFORM_UNSUPPORTED");
    if(!info||!info.isDirectory()||info.isSymbolicLink()||
      info.uid!==uid||(info.mode&0o077)!==0)
      bad("WORKER_DIRECTORY_UNSAFE");
  }
  #fileInfo():boolean{
    this.#parent();
    const stat=lstatSync(this.#path,{throwIfNoEntry:false});
    if(!stat){
      if(this.#written)bad("WORKER_FILE_UNSAFE");
      return false;
    }
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||
      stat.uid!==process.getuid?.()||(stat.mode&0o077)!==0||
      stat.size>MAX_LEDGER)bad("WORKER_FILE_UNSAFE");
    return true;
  }
  #read():JournalRecord[]{
    if(!this.#fileInfo())return [];
    this.#written=true;
    if(typeof constants.O_NOFOLLOW!=="number")bad("WORKER_NOFOLLOW_UNAVAILABLE");
    const fd=openSync(this.#path,constants.O_RDONLY|constants.O_NOFOLLOW);
    let bytes:Buffer;
    try{
      const stat=fstatSync(fd);
      if(!stat.isFile()||stat.nlink!==1||(stat.mode&0o077)!==0||
        stat.uid!==process.getuid?.()||stat.size>MAX_LEDGER)
        bad("WORKER_FILE_UNSAFE");
      bytes=readFileSync(fd);
    }finally{closeSync(fd);}
    if(bytes.length===0)return [];
    let text="";
    try{text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}
    catch{bad("WORKER_JOURNAL_INTEGRITY");}
    if(!text.endsWith("\n"))bad("WORKER_JOURNAL_INTEGRITY");
    const rows=text.slice(0,-1).split("\n");
    if(rows.length>10000)bad("WORKER_JOURNAL_CAPACITY");
    const entries:JournalRecord[]=[];
    let priorHash=GENESIS;
    const latest=new Map<string,JournalRecord>();
    for(const [i,line] of rows.entries()){
      let decoded:unknown;
      try{decoded=JSON.parse(line);}catch{bad("WORKER_JOURNAL_INTEGRITY");}
      if(!isPlain(decoded)||Object.keys(decoded).length!==RECORD_KEYS.size||
        Object.keys(decoded).some(x=>!RECORD_KEYS.has(x))||
        decoded.schema!==SCHEMA||decoded.sequence!==i+1||
        decoded.previousHash!==priorHash||
        typeof decoded.hash!=="string"||!SHA.test(decoded.hash)||
        typeof decoded.at!=="string"||!TIME.test(decoded.at))
        bad("WORKER_JOURNAL_INTEGRITY");
      const data=decoded as Record<string,unknown>;
      const properties=Object.fromEntries(KEYS.map(k=>[k,data[k]]));
      try{metadata(properties);}catch{bad("WORKER_JOURNAL_INTEGRITY");}
      const {hash,...unsigned}=data;
      if(hashFor(unsigned as Omit<JournalRecord,"hash">)!==hash)
        bad("WORKER_JOURNAL_INTEGRITY");
      const row=data as unknown as JournalRecord;
      const before=latest.get(row.runId);
      if((!before&&row.state!=="RUNNING")||
        (before&&before.actorId!==row.actorId)||
        (before&&closed.has(before.state))||
        (before&&row.sentCount<before.sentCount)||
        (before&&row.maxEvents<before.maxEvents)||
        (before&&row.artifactRevisionId!==before.artifactRevisionId))
        bad("WORKER_JOURNAL_INTEGRITY");
      latest.set(row.runId,row);
      entries.push(row);
      priorHash=row.hash;
    }
    return entries;
  }
  record(input:WorkerMetadata):void{
    const value=normalize(input);
    const rows=this.#read();
    if(rows.length>=10000)bad("WORKER_JOURNAL_CAPACITY");
    const previous=rows.filter(x=>x.runId===value.runId).at(-1);
    if((!previous&&value.state!=="RUNNING")||
      (previous&&closed.has(previous.state))||
      (previous&&previous.actorId!==value.actorId)||
      (previous&&previous.artifactRevisionId!==value.artifactRevisionId)||
      (previous&&value.sentCount<previous.sentCount)||
      (previous&&value.maxEvents<previous.maxEvents))
      bad("WORKER_INVALID_TRANSITION");
    const prevHash=rows.at(-1)?.hash??GENESIS;
    const unsigned={schema:SCHEMA,sequence:rows.length+1,
      at:new Date().toISOString(),previousHash:prevHash,...value};
    const row:JournalRecord={...unsigned,hash:hashFor(unsigned)};
    const line=Buffer.from(JSON.stringify(row)+"\n","utf8");
    const existing=this.#fileInfo();
    const size=existing?lstatSync(this.#path).size:0;
    if(size+line.length>MAX_LEDGER)bad("WORKER_JOURNAL_CAPACITY");
    if(typeof constants.O_NOFOLLOW!=="number")bad("WORKER_NOFOLLOW_UNAVAILABLE");
    const flags=constants.O_WRONLY|constants.O_APPEND|constants.O_NOFOLLOW|
      (existing?0:(constants.O_CREAT|constants.O_EXCL));
    let fd=-1;
    try{fd=openSync(this.#path,flags,0o600);}
    catch{bad("WORKER_FILE_UNSAFE");}
    try{
      const stat=fstatSync(fd);
      if(!stat.isFile()||stat.nlink!==1||(stat.mode&0o077)!==0||
        stat.uid!==process.getuid?.())bad("WORKER_FILE_UNSAFE");
      const written=writeSync(fd,line);
      if(written!==line.length)bad("WORKER_JOURNAL_IO_ERROR");
      fsyncSync(fd);
      this.#written=true;
    }finally{closeSync(fd);}
  }
  reconcile(nowMs=Date.now()):WorkerReconciliation[]{
    if(!Number.isFinite(nowMs)||nowMs<0)bad("WORKER_CLOCK_INVALID");
    const rows=this.#read();
    const latest=new Map<string,JournalRecord>();
    for(const record of rows)latest.set(record.runId,record);
    return [...latest.values()].filter(v=>!closed.has(v.state)).map(record=>({
      runId:record.runId,
      state:Date.parse(record.leaseExpiresAt)<=nowMs?
        "EXPIRED_NO_RESTART" as const:"REAPPROVAL_REQUIRED" as const,
      lastKnownSentCount:record.sentCount,
      autoResumeAllowed:false as const,
      originalSourceRestored:false as const,
      sensorIngestVerified:false as const,
    }));
  }
}
