import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {SyntheticSessionController} from "../src/testlab-session.js";
import {TestLabEvidenceLedger} from "../src/testlab-evidence.js";

const route="/api/v1/test-lab/sessions/";
const sample={format:"json" as const,
  source:'{"time":"2026-01-01T00:00:00Z","src_ip":"192.0.2.8","user":"private-sample-user"}',
  seed:22,sequence:0,timestampField:"time",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
};
const headers=(actor:string)=>({"content-type":"application/json","x-test-actor":actor});
const post=(base:string,action:string,body:unknown)=>fetch(base+route+action,{
  method:"POST",headers:headers("alice"),body:JSON.stringify(body),
});
async function withHttp(controller:SyntheticSessionController|undefined,
  fn:(base:string)=>Promise<void>){
  const server=createBackendServer(controller?{
    testLabController:controller,
    authorizeTestLabSession:async request=>{
      const actor=request.headers["x-test-actor"];
      return actor==="alice"||actor==="bob"?actor:null;
    },
  }:{});
  await new Promise<void>(ok=>server.listen(0,"127.0.0.1",ok));
  try{await fn("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>(ok=>server.close(()=>ok()));}
}
test("download is disabled by default; no anonymous evidence is exposed",async()=>{
  await withHttp(undefined,async base=>{
    const request=await fetch(base+route+"evidence-export?runId=test_run_"+"a".repeat(32));
    assert.equal(request.status,403);
    assert.equal((await request.json() as any).error,"TESTLAB_SENDER_DISABLED");
  });
});
test("owner-only evidence download is content-addressed, safe and never inflates proofs",async()=>{
  const controller=new SyntheticSessionController({
    approveStart:async()=>true,evidenceLedger:new TestLabEvidenceLedger(),
    deliver:async()=>{},
  });
  try{
    await withHttp(controller,async base=>{
      const started=await post(base,"start",{sample,
        artifactRevisionId:"a".repeat(64),approvalId:"synthetic-approval-123",
        ratePerSecond:5,leaseMs:1800,maxEvents:15});
      assert.equal(started.status,200);
      const {runId}=await started.json() as {runId:string};
      await new Promise(ok=>setTimeout(ok,235));
      assert.equal((await post(base,"stop",{runId})).status,200);
      const path=route+"evidence-export?runId="+runId;
      const res=await fetch(base+path,{headers:headers("alice")});
      assert.equal(res.status,200);
      assert.match(res.headers.get("content-type")||"",/^application\/json/);
      assert.equal(res.headers.get("cache-control"),"no-store");
      assert.match(res.headers.get("content-disposition")||"",
        /^attachment; filename="testlab-evidence-test_run_[0-9a-f]{32}\.json"$/);
      const bytes=Buffer.from(await res.arrayBuffer());
      const sha=createHash("sha256").update(bytes).digest("hex");
      assert.equal(res.headers.get("x-parser-evidence-sha256"),sha);
      assert.equal(Number(res.headers.get("content-length")),bytes.length);
      const report=JSON.parse(bytes.toString("utf8"));
      assert.equal(report.runId,runId);
      assert.ok(report.counts.generated>=1);
      assert.equal(report.counts.sensorObserved,0);
      assert.equal(report.counts.dpIndexed,0);
      assert.equal(report.liveE2eVerified,false);
      assert.equal(report.runtimeParsingVerified,false);
      assert.equal(report.realSensorVerified,false);
      for(const secret of ["private-sample-user","192.0.2.8","synthetic-approval-123","apiKey"])
        assert.equal(bytes.includes(Buffer.from(secret)),false);
      const same=await fetch(base+path,{headers:headers("alice")});
      assert.equal((await same.arrayBuffer()).byteLength,bytes.length);
      assert.equal(same.headers.get("x-parser-evidence-sha256"),sha);
      assert.equal((await fetch(base+path,{headers:headers("bob")})).status,404);
      assert.equal((await fetch(base+path)).status,403);
      for(const query of ["?runId=wrong","?runId="+runId+"&actor=alice",""]){
        assert.equal((await fetch(base+route+"evidence-export"+query,{
          headers:headers("alice")})).status,422);
      }
      assert.equal((await post(base,"evidence-export",{runId})).status,405);
    });
  }finally{controller.stopAll();}
});

test("owner-only Test Lab comparison summary exposes grouped statuses without log values",async()=>{
  await withHttp(undefined,async base=>{
    const res=await fetch(base+route+"evidence-summary?runId=test_run_"+"e".repeat(32));
    assert.equal(res.status,403);
  });
  const controller=new SyntheticSessionController({
    approveStart:async()=>true,evidenceLedger:new TestLabEvidenceLedger(),
    deliver:async()=>{},
  });
  try{
    await withHttp(controller,async base=>{
      const started=await post(base,"start",{sample,
        artifactRevisionId:"a".repeat(64),approvalId:"synthetic-approval-123",
        ratePerSecond:5,leaseMs:1800,maxEvents:15});
      assert.equal(started.status,200);
      const {runId}=await started.json() as {runId:string};
      await new Promise(ok=>setTimeout(ok,235));
      const path=route+"evidence-summary?runId="+runId;
      const summary=await fetch(base+path,{headers:headers("alice")});
      assert.equal(summary.status,200);
      assert.equal(summary.headers.get("cache-control"),"no-store");
      const result=await summary.json() as any;
      assert.equal(result.contract,"testlab-redacted-summary.v0.1");
      assert.equal(result.comparisonStatus,"NOT_VERIFIED");
      assert.ok(result.counts.generated>=1);
      assert.equal(result.counts.dpIndexed,0);
      assert.deepEqual(result.fieldCoverage,[]);
      assert.deepEqual(result.failureGroups,[]);
      assert.equal(result.liveE2eVerified,false);
      for(const secret of ["private-sample-user","192.0.2.8","synthetic-approval-123"]){
        assert.equal(JSON.stringify(result).includes(secret),false);
      }
      assert.equal((await fetch(base+path,{headers:headers("bob")})).status,404);
      assert.equal((await fetch(base+path)).status,403);
      for(const query of ["?runId=wrong","?runId="+runId+"&owner=alice",""]){
        assert.equal((await fetch(base+route+"evidence-summary"+query,
          {headers:headers("alice")})).status,422);
      }
      assert.equal((await post(base,"evidence-summary",{runId})).status,405);
      await post(base,"stop",{runId});
    });
  }finally{controller.stopAll();}
});
