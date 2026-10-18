import assert from "node:assert/strict";
import test from "node:test";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";

const now=Date.parse("2026-10-12T01:02:03Z");
async function localServer(options:Parameters<typeof createBackendServer>[0],
  run:(base:string)=>Promise<void>){
  const backend=createBackendServer(options);
  await new Promise<void>(resolve=>backend.listen(0,"127.0.0.1",resolve));
  try{await run("http://127.0.0.1:"+(backend.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>backend.close(()=>resolve()));}
}
const post=(base:string,body:unknown)=>fetch(base+"/api/v1/test-lab/scenario/preview",{
  method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify(body),
});
const scenario={
  scenarioId:"synthetic-authentication-story",
  mode:"constant-rate",
  events:[
    {id:"json",sample:{format:"json",source:JSON.stringify({
      src_ip:"192.0.2.7",action:"deny",run_id:"old"}),
      seed:5,sequence:0,runMarkerField:"run_id",
      variableFields:[{path:"src_ip",kind:"ipv4"}]}},
    {id:"cef",sample:{format:"cef",
      source:"CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.8 act=deny run_id=old",
      seed:5,sequence:0,runMarkerField:"run_id",
      variableFields:[{path:"src",kind:"ipv4"}]}},
  ],
};

test("offline scenario preview is unauthorized by default, even without a real sink",async()=>{
  await localServer({},async base=>{
    const response=await post(base,{scenario,sequence:0,ratePerSecond:5});
    assert.equal(response.status,403);
    assert.equal((await response.json() as any).error,"TESTLAB_PREVIEW_NOT_AUTHORIZED");
  });
});

test("offline scenario preview accepts bounded format-family selection without sending",async()=>{
  await localServer({authorizeTestLabPreview:async()=>true,
    syntheticClock:()=>now},async base=>{
    const response=await post(base,{scenario,sequence:1,ratePerSecond:5});
    assert.equal(response.status,200);
    const result=await response.json() as any;
    assert.equal(result.sampleId,"cef");
    assert.equal(result.replayMode,"constant-rate");
    assert.equal(result.sampleFamilyCount,2);
    assert.equal(result.nextDelayMs,200);
    assert.equal(result.safeToSendToSensor,false);
    assert.equal(result.sensorReceivedVerified,false);
    assert.equal(result.preview.runtimeParsingVerified,false);
    assert.ok(result.preview.syntheticEvent.startsWith("CEF:0|Synthetic|FW|1|42|Blocked|8|"));
    assert.ok(result.preview.syntheticEvent.includes("test_run_00000000000000000000000000000000"));
    assert.equal(result.preview.generatedAt,"2026-10-12T01:02:03.000Z");
    assert.equal(JSON.stringify(result).includes("PRIVATE_KEY"),false);
    const caps=(await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any).testLab;
    assert.equal(caps.scenarioOfflinePreviewAvailable,true);
    assert.equal(caps.liveSensorSenderEnabled,false);
  });
});

test("offline scenario preview rejects over-limit and malformed fields without raw logs",async()=>{
  await localServer({authorizeTestLabPreview:async()=>true},async base=>{
    const bad=await post(base,{scenario,sequence:-1,ratePerSecond:5});
    assert.equal(bad.status,422);
    assert.match((await bad.json() as any).error,/TESTLAB_SCENARIO_/);
    const extra=await post(base,{scenario,sequence:1,ratePerSecond:5,
      apiKey:"PRIVATE_KEY_MUST_NOT_LEAK"});
    assert.equal(extra.status,422);
    const err=await extra.json() as any;
    assert.equal(JSON.stringify(err).includes("PRIVATE_KEY"),false);
  });
});
