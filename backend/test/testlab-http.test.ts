import assert from "node:assert/strict";
import test from "node:test";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";

async function server(run:(url:string)=>Promise<void>){
  const backend=createBackendServer({syntheticClock:()=>Date.parse("2026-10-12T01:02:03Z"),
    authorizeTestLabPreview:async()=>true});
  await new Promise<void>(resolve=>backend.listen(0,"127.0.0.1",resolve));
  try{await run("http://127.0.0.1:"+(backend.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>backend.close(()=>resolve()));}
}
function post(base:string,payload:unknown){
  return fetch(base+"/api/v1/test-lab/preview",{method:"POST",
    headers:{"content-type":"application/json"},body:JSON.stringify(payload)});
}

test("test-lab preview is opt-in, format-aware, nondeploying and no network sender",async()=>{
  await server(async base=>{
    const capabilities=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(capabilities.testLab.offlineJsonPreview,true);
    assert.equal(capabilities.testLab.offlineKvPreview,true);
    assert.equal(capabilities.testLab.liveSensorSenderEnabled,false);
    assert.equal(capabilities.testLab.runtimeParsingVerified,false);
    const source=JSON.stringify({time:"2025-02-01T08:00:00Z",
      src_ip:"192.0.2.19",action:"allow",user:"test-old"});
    const result=await post(base,{
      format:"json",source,seed:42,sequence:1,timestampField:"time",
      variableFields:[{path:"src_ip",kind:"ipv4"},{path:"user",kind:"username"}],
    });
    assert.equal(result.status,200);
    assert.equal(result.headers.get("cache-control"),"no-store");
    const body=await result.json() as any;
    assert.equal(body.safeToSendToSensor,false);
    assert.equal(body.runtimeParsingVerified,false);
    assert.equal(body.targetSensorVerified,false);
    assert.equal(JSON.parse(body.syntheticEvent).time,"2026-10-12T01:02:03Z");
    assert.equal(JSON.parse(body.syntheticEvent).action,"allow");
    assert.equal(JSON.stringify(body).includes("test-old"),false);
  });
});

test("test-lab preview rejects unexpected secrets, unsupported parsing families and malformed data",async()=>{
  await server(async base=>{
    const source='{"time":"2025-02-01T08:00:00Z","username":"DO_NOT_ECHO"}';
    const options={format:"json",source,seed:42,sequence:1,
      variableFields:[{path:"username",kind:"username"}]};
    const extra=await post(base,{...options,apiKey:"PRIVATE_SHOULD_NEVER_GO_TO_PREVIEW"});
    assert.equal(extra.status,422);
    assert.equal(JSON.stringify(await extra.json()).includes("PRIVATE_"),false);
    const cef=await post(base,{...options,format:"cef"});
    assert.equal(cef.status,422);
    const err=await cef.json() as any;
    assert.equal(err.error,"TESTLAB_FORMAT_UNSUPPORTED");
    assert.equal(JSON.stringify(err).includes("DO_NOT_ECHO"),false);
    const stale=await post(base,{...options,timestampField:"missing"});
    assert.equal(stale.status,422);
    const wrongMethod=await fetch(base+"/api/v1/test-lab/preview");
    assert.equal(wrongMethod.status,405);
  });
});

test("authenticated Test Lab HTTP generates schema-aligned CSV with current timestamp but no send",async()=>{
  await server(async base=>{
    const cap=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(cap.testLab.offlineCsvPreview,true);
    assert.equal(cap.testLab.liveSensorSenderEnabled,false);
    const input={
      format:"csv",source:'192.0.2.7,443,"deny",2025-01-01T01:02:03Z',
      csvColumns:["src_ip","dst_port","action","event_time"],csvDelimiter:",",
      seed:9,sequence:1,timestampField:"event_time",
      variableFields:[{path:"src_ip",kind:"ipv4"}],
    };
    const preview=await post(base,input);
    assert.equal(preview.status,200);
    const payload=await preview.json() as any;
    assert.equal(payload.format,"csv");
    assert.match(payload.syntheticEvent,/^(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]+,443,deny,2026-10-12T01:02:03Z$/);
    assert.equal(payload.targetSensorVerified,false);
    assert.equal(payload.safeToSendToSensor,false);
    const broken=await post(base,{...input,csvColumns:["src_ip","action"]});
    assert.equal(broken.status,422);
    assert.equal((await broken.json() as any).error,"TESTLAB_CSV_COLUMNS_INVALID");
  });
});
