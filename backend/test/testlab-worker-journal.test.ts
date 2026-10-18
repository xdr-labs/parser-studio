import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,readFileSync,writeFileSync,chmodSync,statSync,symlinkSync,unlinkSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {TestLabWorkerJournal} from "../src/testlab-worker-journal.js";

const RUN="test_run_0123456789abcdef0123456789abcdef";
const started={runId:RUN,actorId:"synthetic-owner",state:"RUNNING" as const,
  leaseExpiresAt:"2026-10-12T03:00:00.000Z",sentCount:0,
  maxEvents:30,artifactRevisionId:"a".repeat(64),
  replayMode:"constant-rate" as const,sampleFamilyCount:2};
const later={...started,state:"STOPPED" as const,sentCount:2};
const folder=()=>mkdtempSync(join(tmpdir(),"parserstudio-worker-journal-"));
const use=(cb:(path:string,base:string)=>void)=>{
  const base=folder(),path=join(base,"run-journal.ndjson");
  try{cb(path,base);}finally{rmSync(base,{recursive:true,force:true});}
};

test("owner-only metadata journal survives restart without storing raw samples or credentials",()=>{
  use((path)=>{
    const journal=new TestLabWorkerJournal(path);
    journal.record(started);
    journal.record({...started,state:"PAUSED",sentCount:1});
    journal.record({...started,state:"RUNNING",sentCount:1});
    const text=readFileSync(path,"utf8");
    assert.equal((statSync(path).mode&0o777),0o600);
    assert.equal(text.trim().split("\n").length,3);
    assert.equal(text.includes("rawEvent"),false);
    assert.equal(text.includes("apiKey"),false);
    const restarted=new TestLabWorkerJournal(path);
    const runs=restarted.reconcile(Date.parse("2026-10-12T02:20:00Z"));
    assert.equal(runs.length,1);
    assert.equal(runs[0]?.runId,RUN);
    assert.equal(runs[0]?.state,"REAPPROVAL_REQUIRED");
    assert.equal(runs[0]?.autoResumeAllowed,false);
    assert.equal(runs[0]?.originalSourceRestored,false);
    assert.equal(runs[0]?.sensorIngestVerified,false);
    assert.equal(runs[0]?.lastKnownSentCount,1);
  });
});

test("finished or expired sessions never recover as running or active",()=>{
  use((path)=>{
    const journal=new TestLabWorkerJournal(path);
    journal.record(started);
    journal.record(later);
    assert.deepEqual(new TestLabWorkerJournal(path).reconcile(Date.parse("2026-10-12T02:20:00Z")),[]);
  });
  use((path)=>{
    const journal=new TestLabWorkerJournal(path);
    journal.record(started);
    const expired=new TestLabWorkerJournal(path).reconcile(Date.parse("2026-10-12T03:30:00Z"));
    assert.equal(expired[0]?.state,"EXPIRED_NO_RESTART");
    assert.equal(expired[0]?.autoResumeAllowed,false);
  });
});

test("tampered hash chain or truncated file fails closed without synthetic source echo",()=>{
  use((path)=>{
    const journal=new TestLabWorkerJournal(path);
    journal.record(started);
    const content=readFileSync(path,"utf8");
    writeFileSync(path,content.replace("synthetic-owner","attacker-owner"),{mode:0o600});
    assert.throws(()=>new TestLabWorkerJournal(path).reconcile(0),/WORKER_JOURNAL_INTEGRITY/);
    writeFileSync(path,content.slice(0,-7),{mode:0o600});
    assert.throws(()=>new TestLabWorkerJournal(path).reconcile(0),/WORKER_JOURNAL_/);
  });
});

test("unsafe directory/file permissions, symlink and raw metadata are rejected",()=>{
  use((path,base)=>{
    const journal=new TestLabWorkerJournal(path);
    assert.throws(()=>journal.record({...started,actorId:"owner\nPRIVATE_KEY"}),/WORKER_EVENT_INVALID/);
    assert.throws(()=>journal.record({...started,rawEvent:"PRIVATE_RAW_EVENT"} as any),
      /WORKER_EVENT_INVALID/);
    assert.throws(()=>journal.record({...started,leaseExpiresAt:"yesterday"}),
      /WORKER_EVENT_INVALID/);
    chmodSync(base,0o777);
    assert.throws(()=>journal.record(started),/WORKER_DIRECTORY_UNSAFE/);
    chmodSync(base,0o700);
    journal.record(started);
    chmodSync(path,0o644);
    assert.throws(()=>journal.record(later),/WORKER_FILE_UNSAFE/);
    chmodSync(path,0o600);
    unlinkSync(path);
    writeFileSync(join(base,"actual.ndjson"),"{}",{mode:0o600});
    symlinkSync(join(base,"actual.ndjson"),path);
    assert.throws(()=>journal.record(later),/WORKER_FILE_UNSAFE/);
  });
});

test("journal rejects inconsistent sent counts, closed-to-running resurrection",()=>{
  use(path=>{
    const journal=new TestLabWorkerJournal(path);
    journal.record(started);
    assert.throws(()=>journal.record({...started,sentCount:31}),/WORKER_EVENT_INVALID/);
    journal.record(later);
    assert.throws(()=>journal.record(started),/WORKER_INVALID_TRANSITION/);
  });
});
