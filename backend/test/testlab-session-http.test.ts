import assert from "node:assert/strict";
import test from "node:test";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {SyntheticSessionController} from "../src/testlab-session.js";

const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
const sample=()=>({
  format:"json" as const,
  source:JSON.stringify({time:"2026-01-01T01:00:00Z",
    src_ip:"192.0.2.8",action:"deny",test:{run_id:"synthetic_initial"}}),
  seed:14,sequence:0,timestampField:"time",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
  runMarkerField:"test.run_id",
});
async function withServer(options:Parameters<typeof createBackendServer>[0],
  run:(base:string)=>Promise<void>){
  const srv=createBackendServer(options);
  await new Promise<void>(resolve=>srv.listen(0,"127.0.0.1",resolve));
  try{await run("http://127.0.0.1:"+(srv.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>srv.close(()=>resolve()));}
}
const post=(base:string,path:string,value:unknown)=>fetch(base+path,{
  method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(value),
});

test("test-lab session controls are unavailable without trusted backend sink/auth",async()=>{
  await withServer({},async base=>{
    const response=await post(base,"/api/v1/test-lab/sessions/start",{
      sample:sample(),approvalId:"owner-approved-session",
      ratePerSecond:5,leaseMs:2000,maxEvents:10,
    });
    assert.equal(response.status,403);
    assert.equal((await response.json() as any).error,"TESTLAB_SENDER_DISABLED");
    const c=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(c.testLab.liveSensorSenderEnabled,false);
    assert.equal(c.testLab.trustedSinkSessionControlAvailable,true);
    assert.equal(c.testLab.sessionDurableAcrossRestart,false);
    assert.equal(c.testLab.sessionMaxRatePerSecond,5);
  });
});

test("trusted synthetic session HTTP Start/Pause/Resume/Stop preserves parser and hides raw source",async()=>{
  const records:string[]=[];
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async content=>{records.push(content);},
  });
  try{
    await withServer({testLabController:runner,
      authorizeTestLabSession:async()=> "actor-a"},async base=>{
      const start=await post(base,"/api/v1/test-lab/sessions/start",{
        sample:sample(),approvalId:"owner-approved-session",
        ratePerSecond:5,leaseMs:4000,maxEvents:25,
      });
      assert.equal(start.status,200);
      const initial=await start.json() as any;
      assert.equal(initial.state,"RUNNING");
      assert.equal(initial.parserLifecycleNotModified,true);
      assert.equal(initial.realSensorVerified,false);
      assert.equal(JSON.stringify(initial).includes("synthetic_initial"),false);
      await sleep(270);
      const query=await fetch(base+"/api/v1/test-lab/sessions/status?runId="+initial.runId);
      assert.equal(query.status,200);
      assert.ok((await query.json() as any).sentCount>=1);
      const pause=await post(base,"/api/v1/test-lab/sessions/pause",{runId:initial.runId});
      assert.equal(pause.status,200);
      const before=records.length;
      await sleep(245);
      assert.equal(records.length,before);
      const resumed=await post(base,"/api/v1/test-lab/sessions/resume",{runId:initial.runId});
      assert.equal(resumed.status,200);
      await sleep(250);
      assert.ok(records.length>before);
      const stop=await post(base,"/api/v1/test-lab/sessions/stop",{runId:initial.runId});
      assert.equal(stop.status,200);
      const stopped=await stop.json() as any;
      assert.equal(stopped.state,"STOPPED");
      assert.equal(stopped.parserLifecycleNotModified,true);
      assert.equal(stopped.sensorIngestVerified,false);
      const sent=records.length;
      await sleep(270);
      assert.equal(records.length,sent);
      assert.ok(records.every(event=>JSON.parse(event).test.run_id===initial.runId));
    });
  }finally{runner.stopAll();}
});

test("no session observation/control without separate trusted backend auth callback",async()=>{
  let emits=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{emits++;},
  });
  try{
    await withServer({testLabController:runner,
      authorizeTestLabSession:async()=>null},async base=>{
      const result=await post(base,"/api/v1/test-lab/sessions/start",{
        sample:sample(),approvalId:"owner-approved-session",
        ratePerSecond:1,leaseMs:900,maxEvents:3,
      });
      assert.equal(result.status,403);
      assert.equal(emits,0);
    });
  }finally{runner.stopAll();}
});

test("HTTP sessions are bound to a trusted principal: other users cannot inspect, pause or stop",async()=>{
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{},
  });
  const as=(actor:string)=>({"content-type":"application/json","x-synthetic-actor":actor});
  try{
    await withServer({testLabController:runner,
      authorizeTestLabSession:async req=>
        req.headers["x-synthetic-actor"]==="actor-a"?"actor-a":
        req.headers["x-synthetic-actor"]==="actor-b"?"actor-b":null,
    },async base=>{
      const started=await fetch(base+"/api/v1/test-lab/sessions/start",{
        method:"POST",headers:as("actor-a"),body:JSON.stringify({
          sample:sample(),approvalId:"owner-approved-session",
          ratePerSecond:1,leaseMs:3000,maxEvents:4,
        }),
      });
      assert.equal(started.status,200);
      const {runId}=await started.json() as {runId:string};
      const foreignStatus=await fetch(base+"/api/v1/test-lab/sessions/status?runId="+runId,{
        headers:as("actor-b"),
      });
      assert.equal(foreignStatus.status,404,"a foreign actor cannot view this session");
      for(const action of ["pause","stop"]){
        const foreign=await fetch(base+"/api/v1/test-lab/sessions/"+action,{
          method:"POST",headers:as("actor-b"),body:JSON.stringify({runId}),
        });
        assert.equal(foreign.status,404,"a foreign actor cannot "+action);
      }
      const stop=await fetch(base+"/api/v1/test-lab/sessions/stop",{
        method:"POST",headers:as("actor-a"),body:JSON.stringify({runId}),
      });
      assert.equal(stop.status,200);
      assert.equal((await stop.json() as any).state,"STOPPED");
    });
  }finally{runner.stopAll();}
});

test("closing the backend listener cancels and purges owned synthetic sessions",async()=>{
  let emitted=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{emitted++;},
  });
  const srv=createBackendServer({testLabController:runner,
    authorizeTestLabSession:async()=> "actor-a",
  });
  try{
    await new Promise<void>(resolve=>srv.listen(0,"127.0.0.1",resolve));
    const base="http://127.0.0.1:"+(srv.address() as AddressInfo).port;
    const started=await post(base,"/api/v1/test-lab/sessions/start",{
      sample:sample(),approvalId:"owner-approved-session",
      ratePerSecond:1,leaseMs:3000,maxEvents:4,
    });
    assert.equal(started.status,200);
    const {runId}=await started.json() as {runId:string};
    await new Promise<void>(resolve=>srv.close(()=>resolve()));
    const sent=emitted;
    await sleep(280);
    assert.equal(emitted,sent,"shutdown must cancel any pending send timers");
    assert.throws(()=>runner.status(runId,"actor-a"),/TESTLAB_SESSION_NOT_FOUND/,
      "no private session data survives controller shutdown");
  }finally{
    if(srv.listening)await new Promise<void>(resolve=>srv.close(()=>resolve()));
    runner.stopAll();
  }
});

test("HTTP renewal requires authenticated run owner and independent backend reapproval",async()=>{
  let approvals=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    approveRenewal:async intent=>{
      approvals++;
      assert.equal(intent.ownerId,"actor-a");
      return true;
    },
    deliver:async()=>{},
  });
  const auth=(owner:string)=>({
    "content-type":"application/json","x-synthetic-actor":owner,
  });
  const cmd=(base:string,path:string,body:unknown,owner:string)=>fetch(base+path,{
    method:"POST",headers:auth(owner),body:JSON.stringify(body),
  });
  try{
    await withServer({testLabController:runner,
      authorizeTestLabSession:async req=>
        req.headers["x-synthetic-actor"]==="actor-a"?"actor-a":
        req.headers["x-synthetic-actor"]==="actor-b"?"actor-b":null,
    },async base=>{
      const started=await cmd(base,"/api/v1/test-lab/sessions/start",{
        sample:sample(),approvalId:"owner-approved-session",
        ratePerSecond:1,leaseMs:900,maxEvents:3,
      },"actor-a");
      assert.equal(started.status,200);
      const {runId}=await started.json() as {runId:string};
      const original=runner.status(runId,"actor-a");
      const renewal={runId,approvalId:"owner-renew-session",
        leaseMs:1600,additionalEvents:15};
      const foreign=await cmd(base,"/api/v1/test-lab/sessions/renew",renewal,"actor-b");
      assert.equal(foreign.status,404,"other actor must not renew a private run");
      assert.equal(approvals,0);
      const bad=await cmd(base,"/api/v1/test-lab/sessions/renew",{
        ...renewal,leaseMs:90000001,
      },"actor-a");
      assert.equal(bad.status,422);
      assert.equal(approvals,0);
      const ok=await cmd(base,"/api/v1/test-lab/sessions/renew",renewal,"actor-a");
      assert.equal(ok.status,200);
      const updated=await ok.json() as any;
      assert.equal(updated.maxEvents,18);
      assert.ok(Date.parse(updated.leaseExpiresAt)>Date.parse(original.leaseExpiresAt));
      assert.equal(approvals,1);
      const stop=await cmd(base,"/api/v1/test-lab/sessions/stop",{runId},"actor-a");
      assert.equal(stop.status,200);
      const denied=await cmd(base,"/api/v1/test-lab/sessions/renew",renewal,"actor-a");
      assert.equal(denied.status,422,"stopped run cannot be resurrected");
    });
  }finally{runner.stopAll();}
});
