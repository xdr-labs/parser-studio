import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {compilePair} from "../src/compiler.js";
import {buildArtifactPackage} from "../src/artifact-package.js";
import {TargetDeploymentCoordinator,type TargetDeploymentApi} from "../src/target-deployment.js";
import {sampleProject} from "./fixture.js";
import type {TargetApplyMockGatewayOptions} from "../src/target-apply-bff.js";
import {TargetApplyMockGateway} from "../src/target-apply-bff.js";

const origin="https://isolated-dp.example.invalid";
const tenant="tenant_simulation";
const pair=compilePair(sampleProject());
const archive=buildArtifactPackage(pair,"1.0.0");
const revision=archive.manifest.artifactRevisionId;
const name=archive.manifest.parserName;
const endpoint="/api/v1/parser-pairs/target/apply";
const defaultInput=()=>({
  artifactRevisionId:revision,approvalId:"owner-approved-123",
  expectedName:name,expectedVersion:"1.0.0",confirmed:true,
});
type MockOverrides={
  approve?:boolean;
  auditFails?:boolean;
  readbackFails?:boolean;
  occupiedPort?:boolean;
  refreshedConflict?:boolean;
  badTarget?:boolean;
  waitWrite?:()=>Promise<void>;
};
function mockGateway(overrides:MockOverrides={}){
  const writes:string[]=[];
  const audits:string[]=[];
  const before:string[]=[];
  const rows:Array<{name:string;version:string;port:number}>=[];
  let catalogs=0;
  let lookups=0;
  const api:TargetDeploymentApi={
    listParsers:async()=>{
      lookups++;
      if(overrides.readbackFails&&writes.length>0)return [];
      return [...rows];
    },
    listCatalogue:async()=>{
      catalogs++;
      if(overrides.occupiedPort||overrides.refreshedConflict&&catalogs>1)
        return [{name:"builtin",port:7123}];
      return [{name:"builtin",port:5800}];
    },
    sensorBindings:async()=>({complete:true,ports:[]}),
    localReservations:async()=>({complete:true,ports:[]}),
    writePair:async request=>{
      writes.push(request.method);
      assert.equal(request.tenant,tenant);
      assert.equal(request.name,name);
      assert.equal(request.port,7123);
      assert.deepEqual(request.files.map(f=>f.sha256).sort(),
        Object.values(archive.manifest.fileHashes).sort());
      await overrides.waitWrite?.();
      rows.push({name:request.name,version:request.version,port:request.port});
      return {httpStatus:200};
    },
  };
  const coordinator=new TargetDeploymentCoordinator({
    target:{origin:overrides.badTarget?"https://dp.example.com":origin,
      tenant,sensorIngestPort:7123},
    permittedOrigins:[overrides.badTarget?"https://dp.example.com":origin],
    api,approve:async()=>overrides.approve!==false,
    audit:async entry=>{audits.push(entry.phase);},
  });
  const options:TargetApplyMockGatewayOptions={
    mode:"MOCK_ONLY",
    authorize:async req=>{
      const id=req.headers["x-test-principal"];
      if(id==="alice"||id==="bob")return {id,tenant};
      if(id==="other-tenant")return {id,tenant:"another_tenant"};
      return null;
    },
    resolveRevision:async(_actor,requested)=>{
      if(requested!==revision)return null;
      return {ownerId:"alice",tenant,pair,artifact:archive};
    },
    getCoordinator:async()=>coordinator,
    audit:async event=>{
      before.push(event.phase+":"+event.status);
      if(overrides.auditFails)throw Error("DO_NOT_LEAK_FAKE_AUDIT_STORE");
    },
  };
  return {gateway:new TargetApplyMockGateway(options),writes,audits,before,
    get lookups(){return lookups;},get catalogs(){return catalogs;}};
}
async function withHttp(gateway:TargetApplyMockGateway|undefined,fn:(base:string)=>Promise<void>){
  const server=createBackendServer(gateway===undefined?{}:{targetApplyMockGateway:gateway});
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{await fn("http://127.0.0.1:"+ (server.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}
function post(base:string,body:unknown,principal="alice",path=endpoint){
  return fetch(base+path,{method:"POST",headers:{"content-type":"application/json",
    "x-test-principal":principal},body:JSON.stringify(body)});
}
function status(base:string,principal="alice",id=revision){
  return fetch(base+endpoint+"/status?artifactRevisionId="+id,{
    headers:{"x-test-principal":principal}});
}
test("default CLI server never advertises or executes general target Apply",async()=>{
  await withHttp(undefined,async base=>{
    const p=await post(base,defaultInput());
    assert.equal(p.status,403);
    assert.equal((await p.json() as any).error,"TARGET_APPLY_DISABLED");
    const s=await status(base);
    assert.equal(s.status,403);
  });
});
test("authenticated mock-only target Apply uses server-owned revision, independent approval, readback and redacted audit",async()=>{
  const mock=mockGateway();
  await withHttp(mock.gateway,async base=>{
    const before=await status(base);
    assert.equal(before.status,200);
    assert.equal((await before.json() as any).status,"NOT_ATTEMPTED");
    const response=await post(base,defaultInput());
    assert.equal(response.status,200);
    const applied=await response.json() as any;
    assert.equal(applied.mode,"MOCK_ONLY");
    assert.equal(applied.status,"MOCK_READBACK_VERIFIED");
    assert.equal(applied.registration.apiReadbackVerified,true);
    assert.equal(applied.realTargetVerified,false);
    assert.equal(applied.registration.targetImportVerified,false);
    assert.equal(applied.selectedParserPort,7123);
    assert.equal(applied.artifactRevisionId,revision);
    const current=await status(base);
    assert.equal((await current.json() as any).status,"MOCK_READBACK_VERIFIED");
    assert.deepEqual(mock.writes,["POST"]);
    assert.deepEqual(mock.audits,["BEFORE","AFTER"]);
    assert.deepEqual(mock.before,["BEFORE:REQUESTED","AFTER:MOCK_READBACK_VERIFIED"]);
    assert.equal(mock.catalogs,2);
    assert.equal(mock.lookups,3);
    assert.equal(JSON.stringify(applied).includes("Base64.strict_decode64"),false);
  });
});
test("body cannot provide DP origin, API Key, fake tenant, raw artifact or override version",async()=>{
  const mock=mockGateway();
  await withHttp(mock.gateway,async base=>{
    for(const extra of [
      {targetOrigin:origin},{tenant},{apiKey:"secret"},{pair},{artifact:archive},
    ]){
      const response=await post(base,{...defaultInput(),...extra});
      // The bundled ZIP would exceed the strict 2-KiB metadata-only body
      // limit and is rejected before checking the allowed request fields.
      const oversized=Buffer.byteLength(JSON.stringify({...defaultInput(),...extra}))>2048;
      assert.equal(response.status,oversized?413:422);
      assert.equal((await response.json() as any).error,
        oversized?"INPUT_TOO_LARGE":"TARGET_APPLY_REQUEST_INVALID");
    }
    const mismatch=await post(base,{...defaultInput(),expectedVersion:"1.0.1"});
    assert.equal(mismatch.status,409);
    assert.equal((await mismatch.json() as any).error,"TARGET_APPLY_VERSION_CONFLICT");
    const wrongName=await post(base,{...defaultInput(),expectedName:"customized_wrong"});
    assert.equal(wrongName.status,409);
    const stale=await post(base,{...defaultInput(),artifactRevisionId:"a".repeat(64)});
    assert.equal(stale.status,404);
    assert.deepEqual(mock.writes,[]);
  });
});
test("missing identity, cross-owner revision and tenant mismatch cannot inspect or write",async()=>{
  const mock=mockGateway();
  await withHttp(mock.gateway,async base=>{
    assert.equal((await post(base,defaultInput(),"nobody")).status,403);
    assert.equal((await post(base,defaultInput(),"bob")).status,404);
    assert.equal((await post(base,defaultInput(),"other-tenant")).status,404);
    assert.equal((await status(base,"bob")).status,200);
    assert.equal((await status(base,"nobody")).status,403);
    assert.deepEqual(mock.writes,[]);
  });
});
test("mock mode rejects non-reserved real DP targets before even the first inventory GET",async()=>{
  const mock=mockGateway({badTarget:true});
  await withHttp(mock.gateway,async base=>{
    const denied=await post(base,defaultInput());
    assert.equal(denied.status,403);
    assert.equal((await denied.json() as any).error,"TARGET_APPLY_MOCK_TARGET_REQUIRED");
    assert.equal(mock.lookups,0);
    assert.deepEqual(mock.writes,[]);
  });
});
test("independent approval, audit outage, and port changes fail closed without writes",async()=>{
  for(const variant of [{approve:false},{auditFails:true},{occupiedPort:true},{refreshedConflict:true}]){
    const mock=mockGateway(variant);
    await withHttp(mock.gateway,async base=>{
      const response=await post(base,defaultInput());
      assert.notEqual(response.status,200);
      assert.deepEqual(mock.writes,[]);
      if(variant.auditFails)
        assert.equal((await response.json() as any).error,"TARGET_APPLY_AUDIT_UNAVAILABLE");
      if(variant.refreshedConflict)assert.equal(mock.catalogs,2);
      assert.equal((await status(base).then(r=>r.json()) as any).status,"DENIED");
    });
  }
});
test("unknown mock readback remains explicitly UNVERIFIED, not a real target PASS",async()=>{
  const mock=mockGateway({readbackFails:true});
  await withHttp(mock.gateway,async base=>{
    const r=await post(base,defaultInput());
    assert.equal(r.status,502);
    assert.equal((await r.json() as any).error,"TARGET_READBACK_UNVERIFIED");
    const s=await status(base).then(r=>r.json()) as any;
    assert.equal(s.status,"UNVERIFIED");
    assert.equal(s.realTargetVerified,false);
    assert.deepEqual(mock.writes,["POST"]);
  });
});
test("wrong HTTP method, content type, large body, bad query and malformed JSON are rejected",async()=>{
  const mock=mockGateway();
  await withHttp(mock.gateway,async base=>{
    assert.equal((await fetch(base+endpoint)).status,405);
    assert.equal((await fetch(base+endpoint+"/status",{method:"POST"})).status,405);
    assert.equal((await fetch(base+endpoint,{method:"POST",headers:{"content-type":"text/plain",
      "x-test-principal":"alice"},body:"hello"})).status,415);
    assert.equal((await fetch(base+endpoint,{method:"POST",headers:{"content-type":"application/json",
      "x-test-principal":"alice"},body:" ".repeat(300000)})).status,413);
    assert.equal((await fetch(base+endpoint,{method:"POST",headers:{"content-type":"application/json",
      "x-test-principal":"alice"},body:"{invalid"})).status,400);
    assert.equal((await status(base,"alice","short")).status,422);
    assert.equal((await fetch(base+endpoint+"/status?artifactRevisionId="+revision+"&tenant=else",
      {headers:{"x-test-principal":"alice"}})).status,422);
    assert.deepEqual(mock.writes,[]);
  });
});
test("second concurrent mock Apply is not allowed; first completion remains authoritative",async()=>{
  let release!:()=>void;
  const wait=new Promise<void>(resolve=>{release=resolve;});
  const mock=mockGateway({waitWrite:async()=>wait});
  await withHttp(mock.gateway,async base=>{
    const first=post(base,defaultInput());
    for(let i=0;i<150&&mock.writes.length===0;i++)
      await new Promise(resolve=>setTimeout(resolve,5));
    assert.deepEqual(mock.writes,["POST"]);
    const second=await post(base,defaultInput());
    assert.equal(second.status,409);
    assert.equal((await second.json() as any).error,"TARGET_APPLY_IN_FLIGHT");
    assert.equal((await status(base).then(r=>r.json()) as any).status,"IN_PROGRESS");
    release();
    assert.equal((await first).status,200);
    assert.equal((await status(base).then(r=>r.json()) as any).status,"MOCK_READBACK_VERIFIED");
    assert.deepEqual(mock.writes,["POST"]);
  });
});
