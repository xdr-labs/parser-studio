import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {TestLabEvidenceLedger} from "../src/testlab-evidence.js";
import {exportRedactedEvidenceReport} from "../src/testlab-report-export.js";

const id="test_run_"+"c".repeat(32);
const actor="synthetic-owner";
const rev="a".repeat(64);
function report(){
  const ledger=new TestLabEvidenceLedger();
  ledger.begin(id,actor,rev);
  ledger.generated(id,actor,0);
  ledger.sendAttempted(id,actor,0);
  ledger.sinkAccepted(id,actor,0);
  ledger.generated(id,actor,1);
  ledger.sendAttempted(id,actor,1);
  ledger.failure(id,actor,1,"SEND_TIMEOUT");
  return ledger.report(id,actor);
}
const clone=(v:unknown)=>JSON.parse(JSON.stringify(v)) as any;
test("redacted evidence export is exact deterministic JSON bytes with verifiable SHA",()=>{
  const first=exportRedactedEvidenceReport(report());
  const second=exportRedactedEvidenceReport(report());
  assert.equal(first.filename,"testlab-evidence-"+id+".json");
  assert.equal(first.sha256,createHash("sha256").update(first.bytes).digest("hex"));
  assert.equal(first.bytes.subarray(-1).toString("utf8"),"\n");
  assert.deepEqual(JSON.parse(first.bytes.toString("utf8")).counts,{
    generated:2,sendAttempted:2,sinkAccepted:1,sensorObserved:0,
    dpIndexed:0,fieldCompared:0,
  });
  // Clock-based expiresAt differs across independent runs, but all fields
  // of a single immutable snapshot are deterministic and byte-identical.
  assert.equal(first.bytes.equals(exportRedactedEvidenceReport(
    JSON.parse(first.bytes.toString("utf8"))).bytes),true);
  assert.equal(first.bytes.includes(Buffer.from("API_KEY")),false);
  assert.equal(second.filename,first.filename);
});
test("unknown fields, raw input, credential hints, altered proof flags are rejected",()=>{
  const valid=report();
  for(const altered of [
    {...clone(valid),rawEvent:"PRIVATE_CUSTOMER_RECORD"},
    {...clone(valid),apiKey:"SECRET"},
    {...clone(valid),liveE2eVerified:true},
    {...clone(valid),runtimeParsingVerified:true},
    {...clone(valid),realSensorVerified:true},
    {...clone(valid),counts:{...valid.counts,dpIndexed:1}},
    {...clone(valid),events:[{...clone(valid.events[0]),rawLog:"PRIVATE"}]},
    {...clone(valid),events:[{...clone(valid.events[0]),dpIndexed:true}]},
    {...clone(valid),events:[{...clone(valid.events[0]),fieldComparison:"FIELDS_MATCHED"}]},
    {...clone(valid),events:[{...clone(valid.events[0]),fields:[{field:"name",status:"MATCH"}]}]},
    {...clone(valid),runId:"../exploit"},
  ])assert.throws(()=>exportRedactedEvidenceReport(altered),/EVIDENCE_EXPORT_INVALID/);
});
