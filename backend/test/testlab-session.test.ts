import assert from "node:assert/strict";
import test from "node:test";
import {SyntheticSessionController} from "../src/testlab-session.js";

const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
const sample=()=>({
  format:"json" as const,
  source:JSON.stringify({time:"2026-01-01T01:02:03Z",src_ip:"192.0.2.5",
    action:"deny",test:{run_id:"synthetic_original"}}),
  seed:47,sequence:0,timestampField:"time",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
  runMarkerField:"test.run_id",
});

test("bounded approved synthetic in-memory sender starts, changes event sequence and stops without touching parser",async()=>{
  const emitted:string[]=[];
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async raw=>{emitted.push(raw);},
  });
  try{
    const begun=await runner.start({
      sample:sample(),approvalId:"owner-test-123",ratePerSecond:5,
      leaseMs:1500,maxEvents:50,
    });
    assert.equal(begun.state,"RUNNING");
    assert.equal(begun.parserLifecycleNotModified,true);
    assert.equal(begun.realSensorVerified,false);
    await sleep(500);
    assert.ok(emitted.length>=2);
    const first=JSON.parse(emitted[0]!);
    assert.equal(first.action,"deny");
    assert.match(first.src_ip,/^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
    assert.equal(first.test.run_id,begun.runId);
    assert.notEqual(emitted[0],emitted[1]);
    const status=runner.status(begun.runId);
    assert.equal(JSON.stringify(status).includes("192.0.2.5"),false);
    assert.equal(JSON.stringify(status).includes("synthetic_original"),false);
    runner.stop(begun.runId);
    const count=emitted.length;
    await sleep(430);
    assert.equal(emitted.length,count);
    assert.equal(runner.status(begun.runId).state,"STOPPED");
    assert.equal(runner.status(begun.runId).parserLifecycleNotModified,true);
  }finally{runner.stopAll();}
});

test("pause, resume and short lease enforce backpressure and automatic expiry",async()=>{
  let sent=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async()=>{sent++;},
  });
  try{
    const start=await runner.start({sample:sample(),
      approvalId:"owner-test-123",ratePerSecond:5,leaseMs:800,maxEvents:100});
    await sleep(240);
    runner.pause(start.runId);
    const paused=sent;
    await sleep(220);
    assert.equal(sent,paused);
    runner.resume(start.runId);
    await sleep(410);
    assert.equal(runner.status(start.runId).state,"EXPIRED");
    const ended=sent;
    await sleep(250);
    assert.equal(sent,ended);
  }finally{runner.stopAll();}
});

test("sender is disabled without backend approval/delivery sink and never retries a failed send",async()=>{
  const notConfigured=new SyntheticSessionController({});
  await assert.rejects(()=>notConfigured.start({sample:sample(),
    approvalId:"owner-test-123",ratePerSecond:5,leaseMs:800,maxEvents:10}),
    /TESTLAB_SENDER_DISABLED/);
  const declined=new SyntheticSessionController({
    approveStart:async()=>false,deliver:async()=>{},
  });
  await assert.rejects(()=>declined.start({sample:sample(),
    approvalId:"owner-test-123",ratePerSecond:5,leaseMs:800,maxEvents:10}),
    /TESTLAB_START_DENIED/);
  let attempts=0;
  const failing=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async()=>{attempts++;throw Error("PRIVATE_SOURCE_SHOULD_NOT_ECHO");},
  });
  try{
    const session=await failing.start({sample:sample(),
      approvalId:"owner-test-123",ratePerSecond:5,leaseMs:800,maxEvents:10});
    await sleep(320);
    assert.equal(failing.status(session.runId).state,"FAILED");
    assert.equal(attempts,1);
    assert.equal(JSON.stringify(failing.status(session.runId)).includes("PRIVATE_SOURCE"),false);
  }finally{failing.stopAll();}
});

test("rate limits, no raw sensor address and session capacity are enforced",async()=>{
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{},maxConcurrent:1,
  });
  try{
    for(const bad of [
      {ratePerSecond:100,leaseMs:800,maxEvents:10},
      {ratePerSecond:0.01,leaseMs:800,maxEvents:10},
      {ratePerSecond:1,leaseMs:90000000,maxEvents:10},
      {ratePerSecond:1,leaseMs:800,maxEvents:1000000},
    ]){
      await assert.rejects(()=>runner.start({
        sample:sample(),approvalId:"owner-test-123",...bad,
      }),/TESTLAB_LIMITS_INVALID/);
    }
    const one=await runner.start({
      sample:sample(),approvalId:"owner-test-123",ratePerSecond:1,
      leaseMs:1300,maxEvents:12,
    });
    await assert.rejects(()=>runner.start({
      sample:sample(),approvalId:"owner-test-123",ratePerSecond:1,
      leaseMs:1300,maxEvents:12,
    }),/TESTLAB_CAPACITY_REACHED/);
    runner.stop(one.runId);
  }finally{runner.stopAll();}
});

test("concurrent Start approvals cannot bypass maximum active session capacity",async()=>{
  let authorize=()=>{};
  const pending=new Promise<void>(resolve=>{authorize=resolve;});
  let entered=0;
  const runner=new SyntheticSessionController({
    maxConcurrent:1,
    approveStart:async()=>{entered++;await pending;return true;},
    deliver:async()=>{},
  });
  const plan={sample:sample(),approvalId:"owner-test-concurrency",
    ratePerSecond:1,leaseMs:1400,maxEvents:4};
  try{
    const first=runner.start(plan);
    const second=runner.start(plan);
    assert.equal(entered,1,"capacity must reserve before asynchronously approving a second start");
    authorize();
    const result=await Promise.allSettled([first,second]);
    assert.equal(result.filter(x=>x.status==="fulfilled").length,1);
    const rejected=result.find(x=>x.status==="rejected");
    assert.ok(rejected&&rejected.status==="rejected");
    assert.match((rejected as PromiseRejectedResult).reason.message,/TESTLAB_CAPACITY_REACHED/);
  }finally{authorize();runner.stopAll();}
});

test("controller shutdown during pending asynchronous approval prevents late session start",async()=>{
  let release=()=>{};
  const approvalBarrier=new Promise<void>(resolve=>{release=resolve;});
  let sends=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>{await approvalBarrier;return true;},
    deliver:async()=>{sends++;},
  });
  const start=runner.start({sample:sample(),approvalId:"owner-test-pending",
    ratePerSecond:1,leaseMs:1000,maxEvents:4,
  });
  try{
    runner.stopAll();
    release();
    await assert.rejects(start,/TESTLAB_SENDER_SHUTDOWN/);
    await sleep(110);
    assert.equal(sends,0,"late approval cannot resurrect a stopped controller");
  }finally{release();runner.stopAll();}
});
