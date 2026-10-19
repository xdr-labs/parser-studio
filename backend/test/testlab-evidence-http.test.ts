import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {SyntheticSessionController} from "../src/testlab-session.js";
import {TestLabEvidenceLedger} from "../src/testlab-evidence.js";

const endpoint="/api/v1/test-lab/sessions/";
const sample={format:"json" as const,
  source:'{"time":"2026-01-01T00:00:00Z","src_ip":"192.0.2.8"}',
  seed:18,sequence:0,timestampField:"time",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
};
const headers=(user:string)=>({"content-type":"application/json","x-test-actor":user});
const post=(base:string,action:string,body:unknown,user="alice")=>fetch(base+endpoint+action,{
  method:"POST",headers:headers(user),body:JSON.stringify(body),
});
async function withServer(controller:SyntheticSessionController|undefined,fn:(base:string)=>Promise<void>){
  const server=createBackendServer(controller?{
    testLabController:controller,
    authorizeTestLabSession:async req=>{
      const owner=req.headers["x-test-actor"];
      return owner==="alice"||owner==="bob"?owner:null;
    },
  }:{});
  await new Promise<void>(ok=>server.listen(0,"127.0.0.1",ok));
  try{await fn("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>(ok=>server.close(()=>ok()));}
}
test("default server does not expose evidence or event content",async()=>{
  await withServer(undefined,async base=>{
    const r=await fetch(base+endpoint+"evidence?runId=test_run_"+"1".repeat(32));
    assert.equal(r.status,403);
    assert.equal((await r.json() as any).error,"TESTLAB_SENDER_DISABLED");
    const caps=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(caps.testLab.redactedSessionEvidenceOptInAvailable,true);
    assert.equal(caps.testLab.redactedEvidenceHttpAvailableWhenInjected,true);
    assert.equal(caps.testLab.evidencePersistedAcrossRestart,false);
    assert.equal(caps.testLab.evidenceMaxEventsPerRun,500);
  });
});
test("owner-only evidence GET exports redacted stages and zero unproven sensor/DP fields",async()=>{
  const evidence=new TestLabEvidenceLedger();
  const controller=new SyntheticSessionController({approveStart:async()=>true,
    evidenceLedger:evidence,deliver:async()=>{}});
  try{
    await withServer(controller,async base=>{
      const started=await post(base,"start",{sample,
        artifactRevisionId:"a".repeat(64),
        approvalId:"owner-review-123",ratePerSecond:5,leaseMs:1800,maxEvents:20});
      assert.equal(started.status,200);
      const {runId}=await started.json() as {runId:string};
      await new Promise(resolve=>setTimeout(resolve,240));
      const r=await fetch(base+endpoint+"evidence?runId="+runId,{
        headers:headers("alice")});
      assert.equal(r.status,200);
      const json=await r.json() as any;
      assert.equal(json.runId,runId);
      assert.ok(json.counts.generated>=1);
      assert.equal(json.counts.generated,json.counts.sinkAccepted);
      assert.equal(json.counts.sensorObserved,0);
      assert.equal(json.counts.dpIndexed,0);
      assert.equal(json.liveE2eVerified,false);
      assert.equal(JSON.stringify(json).includes("192.0.2.8"),false);
      assert.equal(JSON.stringify(json).includes("Bearer"),false);
      assert.equal(r.headers.get("cache-control"),"no-store");
      const foreign=await fetch(base+endpoint+"evidence?runId="+runId,{
        headers:headers("bob")});
      assert.equal(foreign.status,404);
      const denied=await fetch(base+endpoint+"evidence?runId="+runId);
      assert.equal(denied.status,403);
      await post(base,"stop",{runId});
    });
  }finally{controller.stopAll();}
});
test("evidence reports fail closed on unavailable journal, malformed query, wrong method",async()=>{
  const controller=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{},
  });
  try{
    await withServer(controller,async base=>{
      const started=await post(base,"start",{sample,
        approvalId:"owner-review-123",ratePerSecond:5,
        leaseMs:1500,maxEvents:10});
      const {runId}=await started.json() as {runId:string};
      const missingLedger=await fetch(base+endpoint+"evidence?runId="+runId,{
        headers:headers("alice")});
      assert.equal(missingLedger.status,403);
      assert.equal((await missingLedger.json() as any).error,
        "TESTLAB_EVIDENCE_DISABLED");
      for(const query of ["?runId=bad","?runId="+runId+"&actor=alice",""]){
        const r=await fetch(base+endpoint+"evidence"+query,{headers:headers("alice")});
        assert.equal(r.status,422);
      }
      const method=await post(base,"evidence",{runId});
      assert.equal(method.status,405);
      await post(base,"stop",{runId});
    });
  }finally{controller.stopAll();}
});
