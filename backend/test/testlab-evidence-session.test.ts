import test from "node:test";
import assert from "node:assert/strict";
import {SyntheticSessionController} from "../src/testlab-session.js";
import {TestLabEvidenceLedger} from "../src/testlab-evidence.js";

const revision="b".repeat(64);
const sample={format:"json" as const,
  source:'{"time":"2026-01-01T00:00:00Z","src_ip":"192.0.2.2"}',
  seed:12,sequence:0,timestampField:"time",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}]};
const request={sample,artifactRevisionId:revision,
  approvalId:"owner-session-123",ratePerSecond:5,leaseMs:1400,maxEvents:20};
const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
// The sender deliberately unrefs its timers so idle sessions do not keep a
// service alive. A test awaiting its first callback must hold its own bounded
// referenced deadline, otherwise Node 22 cancels the pending Promise when the
// event loop has no active handles.
async function awaitFirstDelivery(started:Promise<void>):Promise<void>{
  let deadline:ReturnType<typeof setTimeout>|undefined;
  try{
    await Promise.race([started,new Promise<never>((_,reject)=>{
      deadline=setTimeout(()=>reject(Error("TESTLAB_DELIVERY_START_TIMEOUT")),2000);
    })]);
  }finally{if(deadline!==undefined)clearTimeout(deadline);}
}

test("opt-in mock session writes local stage counters without sensor/DP claims or source leakage",async()=>{
  const ledger=new TestLabEvidenceLedger();
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async()=>{},
    evidenceLedger:ledger,
  });
  try{
    const started=await runner.start(request,"owner-1");
    await sleep(270);
    const report=ledger.report(started.runId,"owner-1");
    assert.ok(report.counts.generated>=1);
    assert.equal(report.counts.generated,report.counts.sendAttempted);
    assert.equal(report.counts.generated,report.counts.sinkAccepted);
    assert.equal(report.counts.sensorObserved,0);
    assert.equal(report.counts.dpIndexed,0);
    assert.equal(JSON.stringify(report).includes("192.0.2.2"),false);
    runner.stop(started.runId,"owner-1");
  }finally{runner.stopAll();}
});
test("opt-in evidence denies sender start without server-owned actor and revision",async()=>{
  let delivered=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async()=>{delivered++;},
    evidenceLedger:new TestLabEvidenceLedger(),
  });
  try{
    await assert.rejects(()=>runner.start(request),
      /TESTLAB_EVIDENCE_OWNER_REQUIRED/);
    await assert.rejects(()=>runner.start({
      ...request,artifactRevisionId:undefined,
    },"owner-1"),/TESTLAB_EVIDENCE_ARTIFACT_REQUIRED/);
    assert.equal(delivered,0);
  }finally{runner.stopAll();}
});
test("mock sink failure records attempted but not accepted or sensor observed",async()=>{
  const ledger=new TestLabEvidenceLedger();
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async()=>{throw Error("PRIVATE_SOURCE_DO_NOT_ECHO");},
    evidenceLedger:ledger,
  });
  try{
    const started=await runner.start(request,"owner-1");
    await sleep(140);
    const report=ledger.report(started.runId,"owner-1");
    assert.equal(report.counts.sendAttempted,1);
    assert.equal(report.counts.sinkAccepted,0);
    assert.equal(report.events[0]?.errorCode,"SEND_FAILED");
    assert.equal(report.counts.sensorObserved,0);
    assert.equal(JSON.stringify(report).includes("PRIVATE_SOURCE"),false);
  }finally{runner.stopAll();}
});

test("stop during unresolved mock delivery records uncertainty and never claims acceptance",async()=>{
  const ledger=new TestLabEvidenceLedger();
  let enter=()=>{},release=()=>{};
  const entered=new Promise<void>(resolve=>{enter=resolve;});
  const waiting=new Promise<void>(resolve=>{release=resolve;});
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,evidenceLedger:ledger,
    deliver:async()=>{enter();await waiting;},
  });
  try{
    const started=await runner.start(request,"owner-1");
    await awaitFirstDelivery(entered);
    const ended=runner.stop(started.runId,"owner-1");
    assert.equal(ended.state,"STOPPED");
    const report=runner.evidenceReport(started.runId,"owner-1");
    assert.equal(report.counts.generated,1);
    assert.equal(report.counts.sendAttempted,1);
    assert.equal(report.counts.sinkAccepted,0);
    assert.equal(report.events[0]?.errorCode,"SEND_OUTCOME_UNCERTAIN");
    release();
    await sleep(75);
    assert.equal(runner.evidenceReport(started.runId,"owner-1").counts.sinkAccepted,0);
  }finally{release();runner.stopAll();}
});

test("bounded evidence history refuses event quota extension above 500",async()=>{
  const ledger=new TestLabEvidenceLedger();
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,approveRenewal:async()=>true,
    evidenceLedger:ledger,deliver:async()=>{},
  });
  try{
    await assert.rejects(()=>runner.start({...request,maxEvents:501},"owner-1"),
      /TESTLAB_EVIDENCE_EVENT_LIMIT/);
    const started=await runner.start({...request,maxEvents:499},"owner-1");
    await assert.rejects(()=>runner.renew(started.runId,{
      approvalId:"owner-renew-123",leaseMs:5000,additionalEvents:2,
    },"owner-1"),/TESTLAB_EVIDENCE_EVENT_LIMIT/);
    assert.equal(runner.status(started.runId,"owner-1").maxEvents,499);
  }finally{runner.stopAll();}
});
