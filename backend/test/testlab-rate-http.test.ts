import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {SyntheticSessionController} from "../src/testlab-session.js";

const path="/api/v1/test-lab/sessions/";
const sample={format:"json" as const,
  source:'{"timestamp":"2026-01-01T00:00:00Z","src_ip":"192.0.2.1"}',
  seed:13,sequence:0,timestampField:"timestamp",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
};
function call(base:string,action:string,body:unknown,who="owner-a"){
  return fetch(base+path+action,{
    method:"POST",
    headers:{"content-type":"application/json","x-mock-actor":who},
    body:JSON.stringify(body),
  });
}
async function withServer(controller:SyntheticSessionController,
  run:(base:string)=>Promise<void>){
  const server=createBackendServer({
    testLabController:controller,
    authorizeTestLabSession:async req=>{
      const actor=req.headers["x-mock-actor"];
      return actor==="owner-a"||actor==="owner-b"?actor:null;
    },
  });
  await new Promise<void>(ok=>server.listen(0,"127.0.0.1",ok));
  try{await run("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{
    await new Promise<void>(ok=>server.close(()=>ok()));
    controller.stopAll();
  }
}
async function start(base:string){
  const response=await call(base,"start",{sample,artifactRevisionId:"a".repeat(64),
    approvalId:"owner-start-123",ratePerSecond:1,leaseMs:3000,maxEvents:10});
  assert.equal(response.status,200);
  return (await response.json() as {runId:string;leaseExpiresAt:string;maxEvents:number});
}
test("rate endpoint is disabled without backend session and identity",async()=>{
  const server=createBackendServer();
  await new Promise<void>(ok=>server.listen(0,"127.0.0.1",ok));
  try{
    const base="http://127.0.0.1:"+(server.address() as AddressInfo).port;
    const result=await call(base,"rate",{runId:"test_run_"+"1".repeat(32),
      approvalId:"owner-rate-123",ratePerSecond:4});
    assert.equal(result.status,403);
    const capabilities=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(capabilities.testLab.sessionRateChangeRequiresSeparateApproval,true);
    assert.equal(capabilities.testLab.sessionRateChangeConfiguredByDefault,false);
    assert.equal(capabilities.testLab.sessionRateChangeHttpAvailableWhenInjected,true);
  }finally{await new Promise<void>(ok=>server.close(()=>ok()));}
});
test("rate HTTP independently authorizes owner and preserves fixed lease and quota",async()=>{
  let approvals=0;
  const ctrl=new SyntheticSessionController({approveStart:async()=>true,
    approveRateChange:async intent=>{
      approvals++;
      assert.equal(intent.ownerId,"owner-a");
      assert.equal(intent.ratePerSecond,4);
      return true;
    },
    deliver:async()=>{},
  });
  await withServer(ctrl,async base=>{
    const initial=await start(base);
    const cmd={runId:initial.runId,approvalId:"owner-rate-123",ratePerSecond:4};
    const foreign=await call(base,"rate",cmd,"owner-b");
    assert.equal(foreign.status,404);
    assert.equal(approvals,0);
    const updated=await call(base,"rate",cmd,"owner-a");
    assert.equal(updated.status,200);
    const state=await updated.json() as any;
    assert.equal(state.ratePerSecond,4);
    assert.equal(state.leaseExpiresAt,initial.leaseExpiresAt);
    assert.equal(state.maxEvents,initial.maxEvents);
    assert.equal(state.sensorIngestVerified,false);
    assert.equal(approvals,1);
    const stopped=await call(base,"stop",{runId:initial.runId});
    assert.equal(stopped.status,200);
    const late=await call(base,"rate",cmd);
    assert.equal(late.status,422);
  });
});
test("rate HTTP refuses unsafe fields, invalid rate and credentials without controller updates",async()=>{
  const ctrl=new SyntheticSessionController({approveStart:async()=>true,
    approveRateChange:async()=>true,deliver:async()=>{}});
  await withServer(ctrl,async base=>{
    const started=await start(base);
    const clean={runId:started.runId,approvalId:"owner-rate-123",ratePerSecond:4};
    for(const bad of [
      {...clean,apiKey:"secret"},
      {...clean,targetUrl:"https://example.invalid"},
      {...clean,ratePerSecond:10},
      {...clean,ratePerSecond:0},
    ]){
      const r=await call(base,"rate",bad);
      assert.equal(r.status,422);
    }
    const badMethod=await fetch(base+path+"rate");
    assert.equal(badMethod.status,405);
    const other=await call(base,"rate",clean,"unknown");
    assert.equal(other.status,403);
    assert.equal(ctrl.status(started.runId,"owner-a").ratePerSecond,1);
  });
});
test("rate HTTP cannot silently enable changes without independent rate approver",async()=>{
  const ctrl=new SyntheticSessionController({approveStart:async()=>true,deliver:async()=>{}});
  await withServer(ctrl,async base=>{
    const started=await start(base);
    const rejected=await call(base,"rate",{
      runId:started.runId,approvalId:"owner-rate-123",ratePerSecond:5,
    });
    assert.equal(rejected.status,403);
    assert.equal((await rejected.json() as any).error,"TESTLAB_RATE_CHANGE_DISABLED");
  });
});
