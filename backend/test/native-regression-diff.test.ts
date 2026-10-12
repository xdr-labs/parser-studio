import test from "node:test";
import assert from "node:assert/strict";
import {compareSyntheticNativeCaseReports,NativeRegressionError}
  from "../src/native-regression-diff.js";

const sha=(x:string)=>x.repeat(64);
const gitHead=(x:string)=>x.repeat(40);
const report=(head=gitHead("a"))=>({
  kind:"parser-studio.synthetic-native-case-evidence.v0.1",
  origin:"independently-authored-public-synthetic",
  backendHead:head,fixtureSha256:sha("1"),
  ruby:"3.2",fluentd:"1.17.1",
  cases:[
    {id:"synthetic-json",slug:"sample_firewall",status:"PASS",outputSha256:sha("2")},
    {id:"synthetic-kv",slug:"sample_kv",status:"PASS",outputSha256:sha("3")},
    {id:"synthetic-cef",slug:"sample_cef",status:"PASS",outputSha256:sha("4")},
  ],
  sensorTrafficSent:false,
  actualTdAgentOrStellarImport:false,targetImportVerified:false,
});
const changed=()=>structuredClone(report(gitHead("b")));

test("two synthetic native reports compare the same fixture and engine without exposing records",()=>{
  const a=report(),b=changed();
  const result=compareSyntheticNativeCaseReports(a,b);
  assert.equal(result.contract,"parser-studio.synthetic-native-regression.v0.1");
  assert.equal(result.status,"SYNTHETIC_IDENTICAL");
  assert.equal(result.baselineHead,gitHead("a"));
  assert.equal(result.candidateHead,gitHead("b"));
  assert.equal(result.fixtureSha256,sha("1"));
  assert.equal(result.caseCount,3);
  assert.equal(result.unchanged,3);
  assert.deepEqual(result.regressed,[]);
  assert.deepEqual(result.improved,[]);
  assert.deepEqual(result.changedOutputs,[]);
  assert.equal(result.actualTdAgentOrStellarImport,false);
  assert.equal(result.targetImportVerified,false);
  assert.equal(result.sensorTrafficSent,false);
});

test("candidate regressions, recoveries and output changes are redacted and deterministic",()=>{
  const a=report(),b=changed();
  a.cases[2]!.status="RECORD_MISMATCH";
  b.cases[0]!.status="TIME_MISMATCH";
  b.cases[2]!.status="PASS";
  b.cases[1]!.outputSha256=sha("5");
  const result=compareSyntheticNativeCaseReports(a,b);
  assert.equal(result.status,"SYNTHETIC_DIFFERENCE_DETECTED");
  assert.equal(result.unchanged,0);
  assert.deepEqual(result.regressed,[{id:"synthetic-json",slug:"sample_firewall",
    from:"PASS",to:"TIME_MISMATCH"}]);
  assert.deepEqual(result.improved,[{id:"synthetic-cef",slug:"sample_cef",
    from:"RECORD_MISMATCH",to:"PASS"}]);
  assert.deepEqual(result.changedOutputs,[{id:"synthetic-kv",slug:"sample_kv",
    fromSha256:sha("3"),toSha256:sha("5")}]);
  assert.equal(JSON.stringify(result).includes("PRIVATE_PASSWORD"),false);
});

test("different fixture sets, runtime profiles, missing cases or changed identities fail closed",()=>{
  const a=report();
  for(const [name, mutate, code] of [
    ["fixture", (b:any)=>{b.fixtureSha256=sha("f");},"REGRESSION_FIXTURE_MISMATCH"],
    ["unsupported engine", (b:any)=>{b.fluentd="1.18.0";},"REGRESSION_REPORT_INVALID"],
    ["missing", (b:any)=>{b.cases.pop();},"REGRESSION_CASE_SET_MISMATCH"],
    ["id", (b:any)=>{b.cases[0].id="other-event";},"REGRESSION_CASE_SET_MISMATCH"],
    ["slug", (b:any)=>{b.cases[0].slug="sample_other";},"REGRESSION_CASE_SET_MISMATCH"],
    ["duplicate", (b:any)=>{b.cases[2].id=b.cases[0].id;},"REGRESSION_REPORT_INVALID"],
  ] as const){
    const b=changed();mutate(b);
    assert.throws(()=>compareSyntheticNativeCaseReports(a,b),
      (error:unknown)=>error instanceof NativeRegressionError&&error.code===code,name);
  }
});

test("reject untrusted data/false vendor proof even when marked synthetic",()=>{
  const original=report();
  for(const modify of [
    (v:any)=>{v.apiKey="SECRET_API_KEY";},
    (v:any)=>{v.cases[0].rawEvent="PRIVATE_RECORD";},
    (v:any)=>{v.cases[0].id="../secrets";},
    (v:any)=>{v.cases[0].status="TRUSTED";},
    (v:any)=>{v.cases[0].outputSha256="A".repeat(64);},
    (v:any)=>{v.targetImportVerified=true;},
    (v:any)=>{v.sensorTrafficSent=true;},
    (v:any)=>{v.actualTdAgentOrStellarImport=true;},
    (v:any)=>{v.cases[0].status="CALLBACK_COUNT";v.cases[0].outputSha256=sha("5");},
  ]){
    const v=changed();modify(v);
    assert.throws(()=>compareSyntheticNativeCaseReports(original,v),
      (error:unknown)=>error instanceof NativeRegressionError&&
        error.code==="REGRESSION_REPORT_INVALID");
  }
});

test("hash metadata from caller is copied and never references mutable report objects",()=>{
  const a=report(),b=changed();
  const res=compareSyntheticNativeCaseReports(a,b);
  b.cases[0]!.outputSha256=sha("f");
  assert.equal(res.fixtureSha256,sha("1"));
  assert.equal(res.unchanged,3);
  assert.equal(JSON.stringify(res).includes(sha("f")),false);
});
