import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
async function withServer(run:(base:string)=>Promise<void>){
  const server=createBackendServer();
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{await run("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}
const endpoint="/api/v1/parser-pairs/templates";
const options={projectId:"test_synthetic",slug:"synthetic_template",revision:1,
  port:6800,protocols:["udp"]};
async function post(base:string,body:unknown){
  return fetch(base+endpoint+"/instantiate",{
    method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify(body),
  });
}
test("read-only templates endpoint advertises only unverified drafts",async()=>{
  await withServer(async base=>{
    const r=await fetch(base+endpoint);
    assert.equal(r.status,200);
    const body=await r.json() as any;
    assert.equal(body.contract,"parser-template-catalog.v0.1");
    assert.equal(body.offlineOnly,true);
    assert.equal(body.templates.length,6);
    assert.equal(body.templates.every((x:any)=>x.targetVerified===false),true);
    assert.equal(r.headers.get("cache-control"),"no-store");
    const capabilities=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(capabilities.authoring.syntheticStarterTemplatesAvailable,true);
    assert.equal(capabilities.authoring.syntheticStarterTemplatesNativeVerified,false);
    assert.equal(capabilities.authoring.syntheticTemplateHttpAvailable,true);
    const unsupported=await fetch(base+endpoint,{method:"POST"});
    assert.equal(unsupported.status,405);
  });
});
test("POST instantiate returns editable ParserProject without any DP activation",async()=>{
  await withServer(async base=>{
    const r=await post(base,{templateId:"rfc5424",options});
    assert.equal(r.status,200);
    const body=await r.json() as any;
    assert.equal(body.project.extraction.format,"syslog_rfc5424");
    assert.equal(body.project.receiver.port,6800);
    assert.equal(body.targetImportVerified,false);
    assert.equal(body.deployableNow,false);
    assert.equal(body.autodeploy,false);
    const bad=await post(base,{templateId:"rfc5424",
      options:{...options,port:6700}});
    assert.equal(bad.status,422);
    assert.equal((await bad.json() as any).error,"TEMPLATE_PROJECT_INVALID");
  });
});
test("template route rejects raw credentials, unknown fields and invalid request bytes",async()=>{
  await withServer(async base=>{
    const forbidden=await post(base,{templateId:"json",options,apiKey:"SECRET"});
    assert.equal(forbidden.status,422);
    assert.equal((await forbidden.json() as any).error,"TEMPLATE_REQUEST_INVALID");
    const unknown=await post(base,{templateId:"new_vendor",options});
    assert.equal(unknown.status,404);
    const plain=await fetch(base+endpoint+"/instantiate",{
      method:"POST",headers:{"content-type":"text/plain"},body:"x",
    });
    assert.equal(plain.status,415);
    const tooLarge=await post(base,{templateId:"json",options,
      raw:"a".repeat(280000)});
    assert.equal(tooLarge.status,413);
    const wrongMethod=await fetch(base+endpoint+"/instantiate");
    assert.equal(wrongMethod.status,405);
  });
});
