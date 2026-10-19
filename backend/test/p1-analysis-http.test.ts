import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";

const prefix="/api/v1/parser-pairs/";
async function withServer(run:(base:string)=>Promise<void>){
  const server=createBackendServer();
  await new Promise<void>(ok=>server.listen(0,"127.0.0.1",ok));
  try{await run("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>(ok=>server.close(()=>ok()));}
}
const send=(base:string,route:string,input:unknown)=>fetch(base+prefix+route,{
  method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(input),
});
const importPair=()=>{
  const generated=compilePair(sampleProject());
  return {
    name:"customized_sample_firewall",
    confContent:generated.files[0]!.content,
    fragmentContent:generated.files[1]!.content,
  };
};
test("read-only import loss report provides exact editable status without source values",async()=>{
  await withServer(async base=>{
    const source=importPair();
    const response=await send(base,"import-loss-report",source);
    assert.equal(response.status,200);
    const output=await response.json() as any;
    assert.equal(output.contract,"parser-import-loss-report.v0.1");
    assert.equal(output.conversionStatus,"EXACT_EDITABLE");
    assert.equal(output.roundTripVerified,true);
    assert.equal(output.knownConversionLoss,false);
    assert.equal(output.deployableNow,false);
    assert.equal(output.targetImportVerified,false);
    assert.equal(JSON.stringify(output).includes("STELLAR_INIT_BEGIN"),false);
    assert.equal(response.headers.get("cache-control"),"no-store");
    const caps=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(caps.import.redactedImportLossReportHttpAvailable,true);
    assert.equal(caps.import.opaqueImportRemainsReadOnly,true);
    assert.equal(caps.authoring.deterministicNameOnlyMappingHttpAvailable,true);
    assert.equal(caps.authoring.mappingSuggestionsAutoApplied,false);
  });
});
test("opaque private Ruby report is read only and never includes the raw Ruby",async()=>{
  await withServer(async base=>{
    const source=importPair();
    source.fragmentContent="# STELLAR_INIT_BEGIN\n# PRIVATE_VALUE\n# STELLAR_INIT_END";
    const response=await send(base,"import-loss-report",source);
    assert.equal(response.status,200);
    const body=await response.json() as any;
    assert.equal(body.conversionStatus,"OPAQUE_KEEP_ORIGINALS");
    assert.equal(body.knownConversionLoss,null);
    assert.equal(body.unknownContentRisk,true);
    assert.equal(JSON.stringify(body).includes("PRIVATE_VALUE"),false);
  });
});
test("strict import loss bounds reject extra keys, unsafe name, invalid JSON and wrong media",async()=>{
  await withServer(async base=>{
    const extra=await send(base,"import-loss-report",{
      ...importPair(),apiKey:"SECRET"});
    assert.equal(extra.status,422);
    assert.equal((await extra.json() as any).error,"IMPORT_LOSS_INPUT_INVALID");
    const bad=await send(base,"import-loss-report",{
      ...importPair(),name:"../unsafe"});
    assert.equal(bad.status,422);
    assert.equal((await bad.json() as any).error,"PAIR_NAME_INVALID");
    const massive=await send(base,"import-loss-report",{
      ...importPair(),fragmentContent:"x".repeat(2300000)});
    assert.equal(massive.status,413);
    const wrong=await fetch(base+prefix+"import-loss-report",{
      method:"POST",headers:{"content-type":"text/plain"},body:"x"});
    assert.equal(wrong.status,415);
    const notAllowed=await fetch(base+prefix+"import-loss-report");
    assert.equal(notAllowed.status,405);
  });
});
test("mapping suggestion route reviews names only, shows collisions and never applies them",async()=>{
  await withServer(async base=>{
    const response=await send(base,"mapping-suggestions",{
      fieldNames:["src_ip","source.ip","action","random_field"],
      existingDestinations:["action"],
    });
    assert.equal(response.status,200);
    const body=await response.json() as any;
    assert.equal(body.autoApplied,false);
    assert.equal(body.nativeVerified,false);
    assert.equal(body.containsRawValues,false);
    assert.deepEqual(body.unknownFields,["random_field"]);
    assert.equal(body.suggestions.filter((x:any)=>x.status==="DESTINATION_CONFLICT").length,2);
    assert.equal(body.suggestions.find((x:any)=>x.proposedDestination==="action").status,"EXISTING_MAPPING");
  });
});
test("mapping suggestion API rejects malicious keys, raw data, malformed inputs and wrong methods",async()=>{
  await withServer(async base=>{
    for(const bad of [
      {fieldNames:["src_ip"],apiKey:"SECRET"},
      {fieldNames:["__proto__"]},
      {fieldNames:["src_ip"],sample:"PRIVATE_VALUE"},
    ]){
      const res=await send(base,"mapping-suggestions",bad);
      assert.equal(res.status,422);
      assert.equal((await res.json() as any).error,"MAPPING_INPUT_INVALID");
    }
    const noMethod=await fetch(base+prefix+"mapping-suggestions");
    assert.equal(noMethod.status,405);
    const badCharset=await fetch(base+prefix+"mapping-suggestions",{
      method:"POST",headers:{"content-type":"application/json; charset=latin1"},
      body:JSON.stringify({fieldNames:["src_ip"]}),
    });
    assert.equal(badCharset.status,415);
  });
});
