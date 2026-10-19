import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,readFileSync,rmSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {SyntheticSessionController} from "../src/testlab-session.js";
import {TestLabWorkerJournal} from "../src/testlab-worker-journal.js";

const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
const sha="a".repeat(64);
const sample=()=>({format:"json" as const,
  source:JSON.stringify({time:"2026-01-01T01:02:03Z",
    src_ip:"192.0.2.12",action:"deny",test:{run_id:"SECRET_SAMPLE_NOT_PERSISTED"}}),
  seed:21,sequence:0,timestampField:"time",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
  runMarkerField:"test.run_id",
});
const start=()=>({sample:sample(),artifactRevisionId:sha,
  approvalId:"owner-approved-journal",
  ratePerSecond:5,leaseMs:1400,maxEvents:8});

test("journaled session records STARTED, counters, Stop before source purge; no automatic recovery",async()=>{
  const dir=mkdtempSync(join(tmpdir(),"parserstudio-journaled-session-"));
  const path=join(dir,"run-journal.ndjson");
  const journal=new TestLabWorkerJournal(path);
  let count=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{count++;},
    recordTransition:transition=>journal.record(transition),
  });
  try{
    const created=await runner.start(start(),"synthetic-owner");
    await sleep(475);
    const unresolved=new TestLabWorkerJournal(path).reconcile(Date.now());
    assert.equal(unresolved.length,1);
    assert.equal(unresolved[0]?.state,"REAPPROVAL_REQUIRED");
    assert.equal(unresolved[0]?.autoResumeAllowed,false);
    assert.ok(count>=2);
    const ended=runner.stop(created.runId,"synthetic-owner");
    assert.equal(ended.state,"STOPPED");
    assert.deepEqual(new TestLabWorkerJournal(path).reconcile(Date.now()),[],
      "completed Stop is persisted before service exits");
    const raw=readFileSync(path,"utf8");
    assert.ok(raw.includes(created.runId));
    assert.equal(raw.includes("SECRET_SAMPLE_NOT_PERSISTED"),false);
    assert.equal(raw.includes("192.0.2.12"),false);
    assert.equal(raw.includes("apiKey"),false);
    assert.equal(ended.parserLifecycleNotModified,true);
    assert.equal(ended.sensorIngestVerified,false);
  }finally{runner.stopAll();rmSync(dir,{recursive:true,force:true});}
});

test("durable START record fails closed before any event if audit unavailable",async()=>{
  let sends=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async()=>{sends++;},
    recordTransition:()=>{throw Error("PRIVATE_RAW_AUDIT_EXCEPTION");},
  });
  try{
    await assert.rejects(()=>runner.start(start(),"synthetic-owner"),
      (error:unknown)=>error instanceof Error &&
        error.message==="TESTLAB_JOURNAL_UNAVAILABLE");
    await sleep(110);
    assert.equal(sends,0);
  }finally{runner.stopAll();}
});

test("journaled runs require backend-authenticated owner and immutable artifact digest",async()=>{
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{},
    recordTransition:()=>{},
  });
  try{
    await assert.rejects(()=>runner.start(start()),/TESTLAB_JOURNAL_OWNER_REQUIRED/);
    await assert.rejects(()=>runner.start({
      ...start(),artifactRevisionId:"not-a-hash",
    },"synthetic-owner"),/TESTLAB_JOURNAL_ARTIFACT_REQUIRED/);
  }finally{runner.stopAll();}
});

test("Stop always cancels active delivery even when durable STOP journaling fails",async()=>{
  let fail=false, sent=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async()=>{sent++;},
    recordTransition:()=>{if(fail)throw Error("PRIVATE_AUDIT_IO");},
  });
  try{
    const opened=await runner.start(start(),"synthetic-owner");
    await sleep(245);
    fail=true;
    const stopped=runner.stop(opened.runId,"synthetic-owner");
    assert.equal(stopped.state,"STOPPED");
    assert.equal(stopped.errorCode,"TESTLAB_JOURNAL_UNAVAILABLE");
    const before=sent;
    await sleep(330);
    assert.equal(sent,before);
  }finally{runner.stopAll();}
});
