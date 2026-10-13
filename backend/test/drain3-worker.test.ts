import test from "node:test";
import assert from "node:assert/strict";
import {resolve} from "node:path";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {mineDrain3,Drain3WorkerError,validateDrain3Request} from "../src/drain3-worker.js";

const python=process.env.DRAIN3_PYTHON||
 resolve(".tmp/drain3-worker-venv/bin/python");
const request={
 contract:"parser-studio.drain3-input.v0.1" as const,
 training:[
  "ERROR LOGIN from 192.0.2.11 user PRIVATE_ALICE",
  "ERROR LOGIN from 192.0.2.12 user PRIVATE_BOB",
  "INFO LOGOUT from 203.0.113.13 user SECRET_CAROL",
 ],
 holdout:[
  "ERROR LOGIN from 192.0.2.14 user PRIVATE_JOHN",
  "DEBUG unrelated MESSAGE PRIVATE_ACCOUNT",
 ],
};
function assertNoRawValues(value:unknown){
 const text=JSON.stringify(value);
 for(const secret of ["PRIVATE_ALICE","PRIVATE_BOB","SECRET_CAROL",
  "PRIVATE_JOHN","PRIVATE_ACCOUNT","192.0.2.11","203.0.113.13"])
  assert.ok(!text.includes(secret),"Worker output retained untrusted user values");
}
test("P1 Drain3 isolated real engine creates bounded templates with independent holdout, no raw values",async()=>{
 const first=await mineDrain3(request,python);
 const second=await mineDrain3(request,python);
 assert.deepEqual(first,second);
 assert.equal(first.contract,"parser-studio.drain3-reviewed-hints.v0.1");
 assert.equal(first.engine,"Drain3 0.9.11");
 assert.equal(first.sourceCount,3);
 assert.equal(first.accounted,3);
 assert.equal(first.holdoutCount,2);
 assert.equal(first.holdoutMatched,1);
 assert.ok(first.groupCount>0&&first.groupCount<=3);
 assert.equal(first.groups.reduce((a,x)=>a+x.trainingCount,0),3);
 assert.equal(first.persisted,false);
 assert.equal(first.sourceValuesIncluded,false);
 assert.equal(first.nativeParserVerified,false);
 assert.equal(first.targetImportVerified,false);
 assertNoRawValues(first);
});
test("P1 Drain3 refuses all unsafe input shapes and untrusted Python path",async()=>{
 const variants:unknown[]=[
  {...request,credential:"SECRET"},
  {...request,training:[]},
  {...request,training:["PRIVATE\nSECOND"]},
  {...request,training:["PRIVATE\u0000SECOND"]},
  {...request,training:["X".repeat(2100)]},
  {...request,training:Array.from({length:501},()=> "x")},
  {...request,holdout:Array.from({length:501},()=>"x")},
  {...request,training:["Secret ".repeat(13000)]},
  {...request,training:"PRIVATE_RAW_STRING"},
  {...request,training:[{}]},
  {...request,contract:"parser-studio.drain3-eval"},
 ];
 for(const input of variants){
  assert.throws(()=>validateDrain3Request(input),(error:unknown)=>
    error instanceof Drain3WorkerError&&error.code==="DRAIN3_INPUT_UNSUPPORTED");
 }
 await assert.rejects(()=>mineDrain3(request,"relative/python"),(error:unknown)=>
   error instanceof Drain3WorkerError&&error.code==="DRAIN3_RUNTIME_UNAVAILABLE");
 await assert.rejects(()=>mineDrain3(request,"/no/such/trusted/python"),(error:unknown)=>
   error instanceof Drain3WorkerError&&error.code==="DRAIN3_WORKER_UNAVAILABLE");
});
async function withServer(
 options:Parameters<typeof createBackendServer>[0],
 cb:(base:string)=>Promise<void>,
){
 const server=createBackendServer(options);
 await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
 try{await cb("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
 finally{await new Promise<void>(r=>server.close(()=>r()));}
}
const path="/api/v1/parser-pairs/patterns/drain3";
async function post(base:string,data:unknown,principal?:string){
 return fetch(base+path,{method:"POST",headers:{
  "content-type":"application/json",
  ...(principal?{"x-synthetic-principal":principal}:{})},
  body:JSON.stringify(data)});
}
test("P1 Drain3 private endpoint denies default, unauthenticated, unconfirmed and malformed requests",async()=>{
 await withServer(undefined,async base=>{
  const denied=await post(base,{...request,confirmed:true},"owner");
  assert.equal(denied.status,403);
  assert.equal((await denied.json() as any).error,"DRAIN3_DISABLED");
 });
 let authCalls=0;
 await withServer({drain3Worker:{pythonExecutable:python,authorize:async req=>{
  authCalls++;return req.headers["x-synthetic-principal"]==="owner";
 }}},async base=>{
  const denied=await post(base,{...request,confirmed:true});
  assert.equal(denied.status,403);
  assert.equal((await denied.json() as any).error,"DRAIN3_DENIED");
  const unconfirmed=await post(base,{...request,confirmed:false},"owner");
  assert.equal(unconfirmed.status,422);
  assert.equal((await unconfirmed.json() as any).error,"DRAIN3_EXPLICIT_CONFIRMATION_REQUIRED");
  const extra=await post(base,{...request,confirmed:true,apiKey:"PRIVATE_API_KEY"},"owner");
  assert.equal(extra.status,422);
  assert.equal((await extra.text()).includes("PRIVATE_API_KEY"),false);
  const malformed=await fetch(base+path,{method:"POST",
   headers:{"content-type":"application/json","x-synthetic-principal":"owner"},
   body:"{PRIVATE_SECRET"});
  assert.equal(malformed.status,400);
  const wrong=await fetch(base+path);
  assert.equal(wrong.status,405);
  assert.ok(authCalls>=4);
 });
});
test("P1 Drain3 no-source GET capability is owner-only and does not disclose raw samples",async()=>{
 const capability="/api/v1/parser-pairs/patterns/drain3/capabilities";
 await withServer(undefined,async base=>{
   assert.equal((await fetch(base+capability)).status,403);
 });
 let calls=0;
 await withServer({drain3Worker:{pythonExecutable:python,authorize:async req=>{
   calls++;return req.headers["x-synthetic-principal"]==="owner";
 }}},async base=>{
   assert.equal((await fetch(base+capability)).status,403);
   const valid=await fetch(base+capability,{
     headers:{"x-synthetic-principal":"owner"}});
   assert.equal(valid.status,200);
   const body=await valid.json() as any;
   assert.deepEqual(body,{
     contract:"parser-studio.drain3-capabilities.v0.1",
     available:true,requiresExplicitConfirmation:true,
     engine:"Drain3 0.9.11",sameOriginRawSourceTransfer:true,
     noPersistence:true,maxTrainingEvents:500,maxHoldoutEvents:500,
     nativeParserVerified:false,targetImportVerified:false,
     noExternalLlmCalls:true,
   });
   assertNoRawValues(body);
   assert.equal((await fetch(base+capability,{method:"POST",
     headers:{"x-synthetic-principal":"owner"}})).status,405);
 });
 assert.equal(calls,2);
});
test("P1 Drain3 owner-approved HTTP returns only no-storage, no-native template metadata",async()=>{
 await withServer({drain3Worker:{pythonExecutable:python,authorize:async req=>
   req.headers["x-synthetic-principal"]==="owner"}},async base=>{
  const result=await post(base,{...request,confirmed:true},"owner");
  assert.equal(result.status,200);
  const body=await result.json() as any;
  assert.deepEqual({
    contract:body.contract,sourceCount:body.sourceCount,
    holdoutCount:body.holdoutCount,holdoutMatched:body.holdoutMatched,
    persisted:body.persisted,nativeParserVerified:body.nativeParserVerified,
    targetImportVerified:body.targetImportVerified,
  },{
    contract:"parser-studio.drain3-reviewed-hints.v0.1",
    sourceCount:3,holdoutCount:2,holdoutMatched:1,
    persisted:false,nativeParserVerified:false,targetImportVerified:false,
  });
  assertNoRawValues(body);
 });
});
