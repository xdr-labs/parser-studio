import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createBackendServer } from "../src/index.js";
import { sampleProject } from "./fixture.js";
async function withServer(fn:(base:string)=>Promise<void>){
 const srv=createBackendServer();
 await new Promise<void>(resolve=>srv.listen(0,"127.0.0.1",resolve));
 const address=srv.address() as AddressInfo;
 try {await fn("http://127.0.0.1:"+address.port);}
 finally {await new Promise<void>(resolve=>srv.close(()=>resolve()));}
}
function post(base:string,path:string,value:unknown){
 return fetch(base+path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(value)});
}
test("health, validation, generate API and explicit unverified status",async()=>{
 await withServer(async base=>{
  const h=await fetch(base+"/health");assert.equal(h.status,200);
  const schemaResponse=await fetch(base+"/api/v1/parser-pairs/schema");
  assert.equal(schemaResponse.status,200);
  const schema=await schemaResponse.json() as any;
  assert.equal(schema.title,"Parser Studio portable ParserProject v0.1");
  const v=await post(base,"/api/v1/parser-pairs/validate",sampleProject());assert.equal(v.status,200);
  assert.equal((await v.json() as any).ok,true);
  const r=await post(base,"/api/v1/parser-pairs/generate",sampleProject());
  assert.equal(r.status,200);const body=await r.json() as any;
  assert.equal(body.files.length,2);assert.equal(body.manifest.status,"DRAFT");
  assert.equal(body.manifest.targetImportVerified,false);
 });
});
test("reject invalid input, too large input and wrong content types",async()=>{
 await withServer(async base=>{
  const p=sampleProject();p.slug="../bad";
  const r=await post(base,"/api/v1/parser-pairs/generate",p);
  assert.equal(r.status,422);
  const error=await r.json() as any;assert.equal(error.error,"INVALID_PROJECT");assert.equal(error.files,undefined);
  const large=await fetch(base+"/api/v1/parser-pairs/generate",{method:"POST",headers:{"content-type":"application/json"},body:" ".repeat(300000)});
  assert.equal(large.status,413);
  const plain=await fetch(base+"/api/v1/parser-pairs/generate",{method:"POST",headers:{"content-type":"text/plain"},body:"hi"});
  assert.equal(plain.status,415);
  const unknown=await fetch(base+"/unknown");assert.equal(unknown.status,404);
 });
});
