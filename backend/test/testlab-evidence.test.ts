import test from "node:test";
import assert from "node:assert/strict";
import {TestLabEvidenceLedger} from "../src/testlab-evidence.js";

const runId="test_run_"+"a".repeat(32);
const artifactId="b".repeat(64);
const owner="test-owner";
const witness={receiptId:"receipt-12345678",runId,sequence:0,
  artifactRevisionId:artifactId};
function create(){
  let now=100000;
  let sensorChecks=0,dpChecks=0;
  const ledger=new TestLabEvidenceLedger({
    now:()=>now,
    verifySensor:async proof=>{
      sensorChecks++;
      return proof.receiptId==="sensor-observer-123";
    },
    verifyDp:async proof=>{
      dpChecks++;
      if(proof.receiptId!=="dp-observer-1234")return null;
      return {indexed:true,fields:[
        {field:"src_ip",status:"MATCH" as const},
        {field:"action",status:"MISMATCH" as const},
      ]};
    },
  });
  return {ledger,advance:(ms:number)=>{now+=ms;},
    get sensorChecks(){return sensorChecks;},
    get dpChecks(){return dpChecks;}};
}
test("record generated -> send attempted -> sink accepted without implying sensor or DP proof",()=>{
  const {ledger}=create();
  ledger.begin(runId,owner,artifactId);
  ledger.generated(runId,owner,0);
  ledger.sendAttempted(runId,owner,0);
  ledger.sinkAccepted(runId,owner,0);
  const result=ledger.report(runId,owner);
  assert.deepEqual(result.counts,{
    generated:1,sendAttempted:1,sinkAccepted:1,sensorObserved:0,
    dpIndexed:0,fieldCompared:0,
  });
  assert.equal(result.events[0]?.sensorObserved,false);
  assert.equal(result.events[0]?.dpIndexed,false);
  assert.equal(result.liveE2eVerified,false);
  assert.equal(result.realSensorVerified,false);
  assert.equal(result.runtimeParsingVerified,false);
  assert.equal(result.events[0]?.fieldComparison,"NOT_VERIFIED");
});
test("proof-gated sensor and DP stages require independently verified receipts",async()=>{
  const context=create(),ledger=context.ledger;
  ledger.begin(runId,owner,artifactId);
  ledger.generated(runId,owner,0);
  ledger.sendAttempted(runId,owner,0);
  ledger.sinkAccepted(runId,owner,0);
  await assert.rejects(()=>ledger.sensorObserved(runId,owner,0,witness),
    /EVIDENCE_PROOF_UNVERIFIED/);
  assert.equal(ledger.report(runId,owner).counts.sensorObserved,0);
  await ledger.dpReadback(runId,owner,0,{...witness,receiptId:"dp-observer-1234"});
  const partial=ledger.report(runId,owner);
  assert.equal(partial.counts.dpIndexed,1);
  assert.equal(partial.counts.fieldCompared,1);
  assert.equal(partial.events[0]?.fieldComparison,"FIELD_MISMATCH");
  assert.equal(partial.events[0]?.sensorObserved,false);
  await ledger.sensorObserved(runId,owner,0,{...witness,receiptId:"sensor-observer-123"});
  const result=ledger.report(runId,owner);
  assert.equal(result.counts.sensorObserved,1);
  assert.deepEqual(result.events[0]?.fields,[
    {field:"action",status:"MISMATCH"},
    {field:"src_ip",status:"MATCH"},
  ]);
  assert.equal(result.liveE2eVerified,false);
  assert.equal(context.sensorChecks,2);
  assert.equal(context.dpChecks,1);
});
test("stage ordering prevents fabricated sensor/DP proof or accepting without attempting",async()=>{
  const {ledger}=create();
  ledger.begin(runId,owner,artifactId);
  assert.throws(()=>ledger.sendAttempted(runId,owner,0),/EVIDENCE_STAGE_INVALID/);
  ledger.generated(runId,owner,0);
  assert.throws(()=>ledger.sinkAccepted(runId,owner,0),/EVIDENCE_STAGE_INVALID/);
  await assert.rejects(()=>ledger.sensorObserved(runId,owner,0,witness),
    /EVIDENCE_STAGE_INVALID/);
  await assert.rejects(()=>ledger.dpReadback(runId,owner,0,witness),
    /EVIDENCE_STAGE_INVALID/);
  ledger.sendAttempted(runId,owner,0);
  ledger.sinkAccepted(runId,owner,0);
  assert.throws(()=>ledger.sinkAccepted(runId,owner,0),/EVIDENCE_STAGE_DUPLICATE/);
});
test("proof receipt cannot inject event bodies, another sequence or a mismatched revision",async()=>{
  const {ledger}=create();
  ledger.begin(runId,owner,artifactId);
  ledger.generated(runId,owner,0);
  ledger.sendAttempted(runId,owner,0);
  ledger.sinkAccepted(runId,owner,0);
  for(const proof of [
    {...witness,artifactRevisionId:"f".repeat(64)},
    {...witness,sequence:1},
    {...witness,rawLog:"SECRET_CUSTOMER_DATA"},
  ]){
    await assert.rejects(()=>ledger.sensorObserved(runId,owner,0,proof),
      /EVIDENCE_PROOF_INVALID/);
  }
  assert.equal(JSON.stringify(ledger.report(runId,owner)).includes("SECRET_CUSTOMER_DATA"),false);
});
test("actor ownership and run uniqueness are enforced on every evidence operation",()=>{
  const {ledger}=create();
  ledger.begin(runId,owner,artifactId);
  assert.throws(()=>ledger.begin(runId,owner,artifactId),/EVIDENCE_RUN_EXISTS/);
  assert.throws(()=>ledger.generated(runId,"other-owner",0),/EVIDENCE_RUN_NOT_FOUND/);
  assert.throws(()=>ledger.report(runId,"other-owner"),/EVIDENCE_RUN_NOT_FOUND/);
  assert.throws(()=>ledger.generated(runId,owner,501),/EVIDENCE_SEQUENCE_INVALID/);
});
test("failure diagnostics and report export contain codes and field names, never raw log values",()=>{
  const {ledger}=create();
  ledger.begin(runId,owner,artifactId);
  ledger.generated(runId,owner,0);
  ledger.sendAttempted(runId,owner,0);
  ledger.failure(runId,owner,0,"SEND_OUTCOME_UNCERTAIN");
  const report=ledger.report(runId,owner);
  assert.equal(report.events[0]?.errorCode,"SEND_OUTCOME_UNCERTAIN");
  assert.equal(report.counts.sinkAccepted,0);
  assert.equal(report.events[0]?.sensorObserved,false);
  assert.equal(JSON.stringify(report).includes("SECRET"),false);
  assert.throws(()=>ledger.failure(runId,owner,0,
    "PRIVATE_SECRET" as any),/EVIDENCE_FAILURE_CODE_INVALID/);
});
test("finite TTL and bounded event/run retention never auto-recovers a run",()=>{
  let now=500000;
  const ledger=new TestLabEvidenceLedger({now:()=>now,maxRuns:1,maxEventsPerRun:2,
    ttlMs:1000});
  ledger.begin(runId,owner,artifactId);
  ledger.generated(runId,owner,0);
  ledger.generated(runId,owner,1);
  assert.throws(()=>ledger.generated(runId,owner,2),/EVIDENCE_CAPACITY_EXCEEDED/);
  assert.throws(()=>ledger.begin("test_run_"+"c".repeat(32),owner,artifactId),
    /EVIDENCE_CAPACITY_EXCEEDED/);
  now+=1001;
  assert.throws(()=>ledger.report(runId,owner),/EVIDENCE_RUN_NOT_FOUND/);
  ledger.begin("test_run_"+"c".repeat(32),owner,artifactId);
  assert.equal(ledger.report("test_run_"+"c".repeat(32),owner).counts.generated,0);
});
