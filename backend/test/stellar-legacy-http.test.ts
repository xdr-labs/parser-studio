import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createBackendServer,type BackendServerOptions} from "../src/http.js";
import {LegacyPocClient} from "../src/stellar-legacy-client.js";
import {makeLegacyUploadPlan,makeDisposablePocTestPair} from "../src/stellar-legacy-plan.js";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";

const host="https://poc-apac.stellarcyber.cloud",tenant="synthetic_tenant";
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json"}});
async function serverWith(options:BackendServerOptions,run:(base:string)=>Promise<void>){
  const srv=createBackendServer(options);
  await new Promise<void>(resolve=>srv.listen(0,"127.0.0.1",resolve));
  const addr=srv.address() as AddressInfo;
  try{await run("http://127.0.0.1:"+addr.port);}
  finally{await new Promise<void>(resolve=>srv.close(()=>resolve()));}
}
function request(base:string,path:string,payload:unknown){
  return fetch(base+path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(payload)});
}
function disposablePair(){
  const p=sampleProject();p.slug="ps_api_crud_test_a1b2c3";
  p.receiver.port=7891;p.receiver.bindAddress="127.0.0.1";
  return makeDisposablePocTestPair(p);
}

test("Legacy API capabilities do not imply modular upload, live runtime or enabled deployment",async()=>{
  await serverWith({},async base=>{
    const capabilities=await fetch(base+"/api/v1/stellar/legacy/capabilities");
    assert.equal(capabilities.status,200);
    const info=await capabilities.json() as any;
    assert.equal(info.legacyPairCrudVerifiedOnPoc,true);
    assert.equal(info.modularUploadVerified,false);
    assert.equal(info.activationApiVerified,false);
    assert.equal(info.testWritesEnabled,false);
    assert.equal(info.serviceConfigured,false);
    const list=await fetch(base+"/api/v1/stellar/legacy/parsers");
    assert.equal(list.status,503);
    const denied=await request(base,"/api/v1/stellar/legacy/create",{
      pair:disposablePair(),version:"1.0.0",confirmed:true,approvalId:"client-confirmation"});
    assert.equal(denied.status,403);
    assert.equal((await denied.json() as any).error,"LEGACY_WRITES_DISABLED");
    const modular=await fetch(base+"/api/v1/stellar/modular/activate");
    assert.equal(modular.status,404);
  });
});

test("read-only list and catalogue are tenant-scoped, credential-free in UI response, backend read-gated",async()=>{
  let auth=0;
  const client=new LegacyPocClient({host,tenant,apiKey:"KEY_PRIVATE",fetchImpl:async(input,init)=>{
    const url=new URL(String(input));
    if(url.pathname.endsWith("/access_token")){auth++;return json({access_token:"JWT_PRIVATE"});}
    if(url.pathname.endsWith("/parsers"))return json({data:[{port:7891,comment:"DO_NOT_ECHO"}]});
    return json({data:[{parser_name:"customized_sample",version:"2.1",cust_id:tenant,
      port:7890,key:"DO_NOT_ECHO"}]});
  }});
  await serverWith({legacyClient:client},async base=>{
    const denied=await fetch(base+"/api/v1/stellar/legacy/parsers");
    assert.equal(denied.status,403);
    assert.equal(auth,0);
  });
  await serverWith({legacyClient:client,authorizeLegacyRead:async()=>true},async base=>{
    const list=await fetch(base+"/api/v1/stellar/legacy/parsers");
    assert.equal(list.status,200);
    const records=await list.json() as any;
    assert.equal(records.parsers[0].name,"customized_sample");
    assert.equal(records.parsers[0].version,"2.1");
    assert.equal(JSON.stringify(records).includes("DO_NOT_ECHO"),false);
    assert.equal(JSON.stringify(records).includes("KEY_PRIVATE"),false);
    const catalogue=await fetch(base+"/api/v1/stellar/legacy/catalogue");
    assert.equal(catalogue.status,200);
    assert.equal((await catalogue.json() as any).catalogue[0].port,7891);
    assert.equal(auth,1);
  });
});

test("Legacy preflight verifies compile result and returns safe plan metadata, never uploads",async()=>{
  await serverWith({},async base=>{
    const pair=compilePair(sampleProject());
    const res=await request(base,"/api/v1/stellar/legacy/prepare",
      {pair,tenant,version:"1.0.0"});
    assert.equal(res.status,200);
    const body=await res.json() as any;
    assert.equal(body.name,"customized_sample_firewall");
    assert.equal(body.proof.targetImportVerified,false);
    assert.equal(body.testOnlyWriteEligible,false);
    assert.equal(body.apiRegistrationVerified,false);
    assert.equal(JSON.stringify(body).includes("STELLAR_INIT_BEGIN"),false);
    assert.equal(JSON.stringify(body).includes(pair.files[0]!.content),false);
    const testPair=disposablePair();
    const safe=await request(base,"/api/v1/stellar/legacy/prepare",
      {pair:testPair,tenant,version:"1.0.0"});
    assert.equal(safe.status,200);
    assert.equal((await safe.json() as any).testOnlyWriteEligible,true);
    const changed=structuredClone(pair);
    changed.files[0]!.bytes++;
    const corrupt=await request(base,"/api/v1/stellar/legacy/prepare",
      {pair:changed,tenant,version:"1.0.0"});
    assert.equal(corrupt.status,422);
    const error=await corrupt.json() as any;
    assert.equal(JSON.stringify(error).includes("STELLAR_INIT_BEGIN"),false);
  });
});

test("Legacy test-only routes require backend enable + approval and verify CREATE read-back",async()=>{
  const records:Array<{parser_name:string;version:string;port:number;cust_id:string}>=[];
  const methods:string[]=[];
  const client=new LegacyPocClient({
    host,tenant,apiKey:"KEY_PRIVATE",fetchImpl:async(input,init)=>{
      const url=new URL(String(input)),method=init?.method||"GET";
      if(url.pathname.endsWith("/access_token"))return json({access_token:"JWT_PRIVATE"});
      if(url.pathname.endsWith("/parsers"))return json({data:[{port:7123}]});
      if(method==="GET")return json({data:records});
      methods.push(method);
      if(method==="POST"){
        const form=init?.body as FormData;
        records.push({parser_name:String(form.get("parser_name")),version:String(form.get("version")),port:7891,cust_id:tenant});
        return json({});
      }
      throw Error("unexpected synthetic HTTP");
    },
    approveWrite:async()=>true,
    audit:async()=>{},
  });
  await serverWith({legacyClient:client,authorizeLegacyRead:async()=>true},async base=>{
    const denied=await request(base,"/api/v1/stellar/legacy/create",
      {pair:disposablePair(),confirmed:true,approvalId:"owner-allow",version:"1.0.0"});
    assert.equal(denied.status,403);
    assert.equal(methods.length,0);
  });
  await serverWith({legacyClient:client,authorizeLegacyRead:async()=>true,
    legacyTestWritesEnabled:true},async base=>{
    const created=await request(base,"/api/v1/stellar/legacy/create",
      {pair:disposablePair(),tenant,confirmed:true,approvalId:"owner-allow",version:"1.0.0"});
    assert.equal(created.status,200);
    const result=await created.json() as any;
    assert.equal(result.apiRegistrationVerified,true);
    assert.equal(result.runtimeParsingVerified,false);
    assert.equal(result.targetImportVerified,false);
    assert.deepEqual(methods,["POST"]);
    assert.equal(JSON.stringify(result).includes("KEY_PRIVATE"),false);
    const crossTenant=await request(base,"/api/v1/stellar/legacy/create",
      {pair:disposablePair(),tenant:"cross-tenant",confirmed:true,approvalId:"owner-allow",version:"1.0.0"});
    assert.equal(crossTenant.status,422);
    assert.deepEqual(methods,["POST"]);
  });
});
