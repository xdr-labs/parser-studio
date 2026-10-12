import test from "node:test";
import assert from "node:assert/strict";
import {SyntheticSessionController} from "../src/testlab-session.js";

const sample={
  format:"json" as const,
  source:'{"timestamp":"2026-01-01T00:00:00Z","src_ip":"192.0.2.8"}',
  seed:51,sequence:0,timestampField:"timestamp",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
};
const plan={sample,approvalId:"owner-start-123",ratePerSecond:1,
  leaseMs:1500,maxEvents:20};
const wait=(ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms));

test("rate cannot change without separate backend approval or under another owner",async()=>{
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{},
  });
  try{
    const started=await runner.start(plan,"owner-a");
    await assert.rejects(()=>runner.changeRate(started.runId,{
      approvalId:"owner-rate-123",ratePerSecond:5,
    },"owner-a"),/TESTLAB_RATE_CHANGE_DISABLED/);
    assert.equal(runner.status(started.runId,"owner-a").ratePerSecond,1);
    await assert.rejects(()=>runner.changeRate(started.runId,{
      approvalId:"owner-rate-123",ratePerSecond:5,
    },"stranger"),/TESTLAB_SESSION_NOT_FOUND/);
    assert.equal(runner.status(started.runId,"owner-a").ratePerSecond,1);
  }finally{runner.stopAll();}
});
test("approved rate changes update bounded timing without extending lease or quota",async()=>{
  let approved=0,sends=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    approveRateChange:async intent=>{
      approved++;
      assert.equal(intent.ownerId,"owner-a");
      assert.equal(intent.currentRatePerSecond,1);
      assert.equal(intent.ratePerSecond,5);
      return true;
    },
    deliver:async()=>{sends++;},
  });
  try{
    const initial=await runner.start(plan,"owner-a");
    const changed=await runner.changeRate(initial.runId,{
      approvalId:"owner-rate-123",ratePerSecond:5,
    },"owner-a");
    assert.equal(changed.ratePerSecond,5);
    assert.equal(changed.maxEvents,initial.maxEvents);
    assert.equal(changed.leaseExpiresAt,initial.leaseExpiresAt);
    await wait(570);
    assert.ok(sends>=2);
    assert.equal(approved,1);
  }finally{runner.stopAll();}
});
test("rate-change enforces valid bounds and independent denial before schedule change",async()=>{
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    approveRateChange:async()=>false,deliver:async()=>{},
  });
  try{
    const started=await runner.start(plan,"owner-a");
    for(const invalid of [0,0.1,5.1,Infinity,NaN]){
      await assert.rejects(()=>runner.changeRate(started.runId,{
        approvalId:"owner-rate-123",ratePerSecond:invalid,
      },"owner-a"),/TESTLAB_RATE_CHANGE_LIMITS_INVALID/);
    }
    await assert.rejects(()=>runner.changeRate(started.runId,{
      approvalId:"owner-rate-123",ratePerSecond:5,
    },"owner-a"),/TESTLAB_RATE_CHANGE_DENIED/);
    assert.equal(runner.status(started.runId,"owner-a").ratePerSecond,1);
  }finally{runner.stopAll();}
});
test("no stale asynchronous rate approval can resume a terminal session",async()=>{
  let release=()=>{};
  const barrier=new Promise<void>(resolve=>{release=resolve;});
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    approveRateChange:async()=>{await barrier;return true;},
    deliver:async()=>{},
  });
  try{
    const started=await runner.start(plan,"owner-a");
    const pending=runner.changeRate(started.runId,{
      approvalId:"owner-rate-123",ratePerSecond:5,
    },"owner-a");
    runner.stop(started.runId,"owner-a");
    release();
    await assert.rejects(pending,/TESTLAB_SESSION_NOT_RUNNING/);
    assert.equal(runner.status(started.runId,"owner-a").state,"STOPPED");
  }finally{release();runner.stopAll();}
});
test("backpressure: pausing during unresolved mock delivery is terminal UNCERTAIN, never replays",async()=>{
  let enter=()=>{},release=()=>{};
  const entered=new Promise<void>(resolve=>{enter=resolve;});
  const hanging=new Promise<void>(resolve=>{release=resolve;});
  let attempts=0,signal:AbortSignal|undefined;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    deliver:async(_event,context)=>{
      attempts++;signal=context.signal;enter();await hanging;
    },
  });
  try{
    const started=await runner.start({...plan,ratePerSecond:5},"owner-a");
    await entered;
    const paused=runner.pause(started.runId,"owner-a");
    assert.equal(paused.state,"FAILED");
    assert.equal(paused.errorCode,"TESTLAB_SEND_OUTCOME_UNCERTAIN");
    assert.equal(signal?.aborted,true);
    assert.throws(()=>runner.resume(started.runId,"owner-a"),
      /TESTLAB_SESSION_NOT_PAUSED/);
    release();
    await wait(320);
    assert.equal(attempts,1);
    assert.equal(runner.status(started.runId,"owner-a").sentCount,0);
  }finally{release();runner.stopAll();}
});
test("concurrent rate approvals cannot double-change a session",async()=>{
  let release=()=>{};
  const barrier=new Promise<void>(resolve=>{release=resolve;});
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,
    approveRateChange:async()=>{await barrier;return true;},
    deliver:async()=>{},
  });
  try{
    const s=await runner.start(plan,"owner-a");
    const change={approvalId:"owner-rate-123",ratePerSecond:4};
    const first=runner.changeRate(s.runId,change,"owner-a");
    const second=runner.changeRate(s.runId,change,"owner-a");
    release();
    const settled=await Promise.allSettled([first,second]);
    assert.equal(settled.filter(x=>x.status==="fulfilled").length,1);
    assert.equal(settled.filter(x=>x.status==="rejected").length,1);
    assert.equal(runner.status(s.runId,"owner-a").ratePerSecond,4);
  }finally{release();runner.stopAll();}
});
