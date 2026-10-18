import test from "node:test";
import assert from "node:assert/strict";
import {pollBoundedInterflow} from "../src/stellar-interflow-poll.js";
import type {InterflowFieldResult} from "../src/stellar-interflow.js";

const fields=[{field:"srcip",status:"MATCH" as const}];
const asResult=(state:InterflowFieldResult["state"]):InterflowFieldResult=>({
  state,matchCount:state==="NO_MATCH"?0:1,
  fields:state==="NO_MATCH"?[]:fields,
  sensorReceivedVerified:false,endToEndVerified:false,
  runtimeParsingVerified:false,targetImportVerified:false,
});

test("bounded Interflow polling stops at first complete field match without returning raw sources",async()=>{
  let attempts=0;
  const result=await pollBoundedInterflow(async()=>{
    attempts++;
    return attempts<3?asResult("NO_MATCH"):asResult("MATCHED_RESPONSE_FIELDS");
  },{
    maxAttempts:4,intervalMs:250,signal:new AbortController().signal,
  });
  assert.equal(attempts,3);
  assert.equal(result.attempts,3);
  assert.equal(result.state,"MATCHED_RESPONSE_FIELDS");
  assert.equal(result.endToEndVerified,false);
  assert.equal(result.cursorVerified,false);
  assert.equal(result.searchPermissionsVerified,false);
});

test("Interflow polling max attempts preserves NO_MATCH and field mismatch truthfully",async()=>{
  let attempts=0;
  const result=await pollBoundedInterflow(async()=>{
    attempts++;
    return asResult(attempts===1?"FIELD_MISMATCH":"NO_MATCH");
  },{
    maxAttempts:3,intervalMs:250,signal:new AbortController().signal,
  });
  assert.equal(attempts,3);
  assert.equal(result.state,"FIELD_MISMATCH");
  assert.equal(result.attempts,3);
  assert.equal(result.endToEndVerified,false);
});

test("polling is cancelled promptly and does not retry upstream authorization/transport errors",async()=>{
  let attempts=0;
  const controller=new AbortController();
  const outstanding=pollBoundedInterflow(async()=>{
    attempts++;
    return asResult("NO_MATCH");
  },{
    maxAttempts:5,intervalMs:2500,signal:controller.signal,
  });
  await new Promise(resolve=>setTimeout(resolve,60));
  controller.abort();
  await assert.rejects(outstanding,/INTERFLOW_POLL_CANCELLED/);
  assert.equal(attempts,1,"aborted user request cannot keep background polling");
  let deniedCalls=0;
  await assert.rejects(()=>pollBoundedInterflow(async()=>{
    deniedCalls++;
    throw Error("UPSTREAM_403_DENIED");
  },{
    maxAttempts:5,intervalMs:250,signal:new AbortController().signal,
  }),/UPSTREAM_403_DENIED/);
  assert.equal(deniedCalls,1,"authorization failures never retry");
});

test("unsafe polling frequency and unbounded durations are rejected before any query",async()=>{
  let calls=0;
  for(const opts of [
    {maxAttempts:0,intervalMs:1000},
    {maxAttempts:7,intervalMs:1000},
    {maxAttempts:3,intervalMs:5},
    {maxAttempts:3,intervalMs:6000},
    {maxAttempts:6,intervalMs:4000},
  ]){
    await assert.rejects(()=>pollBoundedInterflow(async()=>{
      calls++;return asResult("NO_MATCH");
    },{...opts,signal:new AbortController().signal}),/INTERFLOW_POLL_LIMITS_INVALID/);
  }
  assert.equal(calls,0);
});
