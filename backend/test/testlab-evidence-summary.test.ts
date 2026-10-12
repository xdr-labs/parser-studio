import test from "node:test";
import assert from "node:assert/strict";
import {TestLabEvidenceLedger} from "../src/testlab-evidence.js";
import {summarizeRedactedEvidenceReport} from "../src/testlab-evidence-summary.js";

const id="test_run_"+"e".repeat(32);
const actor="synthetic-owner";
const revision="a".repeat(64);
const receipt=(sequence:number)=>({receiptId:"redacted-receipt-"+sequence,
  runId:id,sequence,artifactRevisionId:revision});
const ledger=()=>new TestLabEvidenceLedger({
  verifyDp:async proof=>({
    indexed:true,fields:proof.sequence===0?[
      {field:"src_ip",status:"MATCH" as const},
      {field:"user",status:"MISMATCH" as const},
    ]:[
      {field:"action",status:"MATCH" as const},
      {field:"src_ip",status:"MISSING" as const},
      {field:"user",status:"MATCH" as const},
    ],
  }),
});

test("offline evidence summary groups redacted failures and measured per-field coverage only",async()=>{
  const h=ledger();h.begin(id,actor,revision);
  for(const index of [0,1,2]){
    h.generated(id,actor,index);h.sendAttempted(id,actor,index);
    if(index===1)h.failure(id,actor,index,"SEND_TIMEOUT");
    else{
      h.sinkAccepted(id,actor,index);
      await h.dpReadback(id,actor,index,receipt(index));
    }
  }
  const summary=summarizeRedactedEvidenceReport(h.report(id,actor));
  assert.equal(summary.contract,"testlab-redacted-summary.v0.1");
  assert.equal(summary.runId,id);
  assert.equal(summary.comparisonStatus,"OFFLINE_EVIDENCE_ONLY");
  assert.deepEqual(summary.counts,{generated:3,sendAttempted:3,sinkAccepted:2,
    sensorObserved:0,dpIndexed:2,fieldCompared:2});
  assert.deepEqual(summary.failureGroups,[{errorCode:"SEND_TIMEOUT",events:1}]);
  assert.deepEqual(summary.fieldCoverage,[
    {field:"action",comparedEvents:1,matched:1,mismatched:0,missing:0,
      coveragePercent:50,matchPercent:100},
    {field:"src_ip",comparedEvents:2,matched:1,mismatched:0,missing:1,
      coveragePercent:100,matchPercent:50},
    {field:"user",comparedEvents:2,matched:1,mismatched:1,missing:0,
      coveragePercent:100,matchPercent:50},
  ]);
  assert.equal(summary.realSensorVerified,false);
  assert.equal(summary.runtimeParsingVerified,false);
  assert.equal(summary.liveE2eVerified,false);
  assert.equal(JSON.stringify(summary).includes("redacted-receipt"),false);
});

test("unobserved DP always reports NOT_VERIFIED rather than inferred field matches",()=>{
  const h=ledger();h.begin(id,actor,revision);
  h.generated(id,actor,0);h.sendAttempted(id,actor,0);h.sinkAccepted(id,actor,0);
  const result=summarizeRedactedEvidenceReport(h.report(id,actor));
  assert.equal(result.comparisonStatus,"NOT_VERIFIED");
  assert.deepEqual(result.fieldCoverage,[]);
  assert.deepEqual(result.failureGroups,[]);
  assert.equal(result.counts.dpIndexed,0);
});

test("summary rejects injected secrets, changed counts, forged DP proof and unbounded metadata",()=>{
  const h=ledger();h.begin(id,actor,revision);
  h.generated(id,actor,0);
  const report=h.report(id,actor);
  const mutate=(f:(v:any)=>void)=>{
    const copy=JSON.parse(JSON.stringify(report));f(copy);return copy;
  };
  for(const tamper of [
    mutate(v=>v.apiKey="SECRET_KEY"),
    mutate(v=>v.events[0].rawEvent="CUSTOMER_LOG"),
    mutate(v=>v.events[0].dpIndexed=true),
    mutate(v=>v.counts.generated=7),
    mutate(v=>v.liveE2eVerified=true),
    mutate(v=>v.events[0].fields=[{field:"secret",status:"MATCH"}]),
  ]){
    assert.throws(()=>summarizeRedactedEvidenceReport(tamper),/EVIDENCE_EXPORT_INVALID/);
  }
});
