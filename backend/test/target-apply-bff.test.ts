import test from "node:test";
import assert from "node:assert/strict";
import type {IncomingMessage} from "node:http";
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
const alice={id:"alice",tenant};
const bob={id:"bob",tenant};
const outsider={id:"other-tenant",tenant:"another_tenant"};
const request=(actor:string)=>({headers:{"x-test-principal":actor}} as unknown as IncomingMessage);

test("authenticated mock-only Apply checks trusted revision, checksum, approval and GET readback",async()=>{
  const mock=mockGateway();
  const actor=await mock.gateway.authenticate(request("alice"));
  assert.deepEqual(actor,alice);
  assert.equal(mock.gateway.status(alice,revision).status,"NOT_ATTEMPTED");
  const result=await mock.gateway.apply(alice,defaultInput());
  assert.equal(result.mode,"MOCK_ONLY");
  assert.equal(result.status,"MOCK_READBACK_VERIFIED");
  assert.equal(result.artifactRevisionId,revision);
  assert.equal(result.selectedParserPort,7123);
  assert.equal(result.realTargetVerified,false);
  assert.equal(result.registration.targetImportVerified,false);
  assert.deepEqual(mock.writes,["POST"]);
  assert.deepEqual(mock.audits,["BEFORE","AFTER"]);
  assert.deepEqual(mock.before,["BEFORE:REQUESTED","AFTER:MOCK_READBACK_VERIFIED"]);
  assert.equal(mock.catalogs,2);
  assert.equal(mock.lookups,3);
  assert.equal(mock.gateway.status(alice,revision).status,"MOCK_READBACK_VERIFIED");
  assert.equal(JSON.stringify(result).includes("Base64.strict_decode64"),false);
});
test("authentication, revision owner and tenant separation fail closed",async()=>{
  const mock=mockGateway();
  assert.equal(await mock.gateway.authenticate(request("unauthorized")),null);
  assert.deepEqual(await mock.gateway.authenticate(request("alice")),alice);
  assert.deepEqual(await mock.gateway.authenticate(request("bob")),bob);
  await assert.rejects(()=>mock.gateway.apply(bob,defaultInput()),
    /TARGET_APPLY_REVISION_NOT_FOUND/);
  await assert.rejects(()=>mock.gateway.apply(outsider,defaultInput()),
    /TARGET_APPLY_REVISION_NOT_FOUND/);
  assert.equal(mock.gateway.status(bob,revision).status,"NOT_ATTEMPTED");
  assert.deepEqual(mock.writes,[]);
});
test("request cannot inject URL, tenant, key or Ruby pair through Apply boundary",async()=>{
  const mock=mockGateway();
  for(const extra of [{tenant},{targetOrigin:origin},{apiKey:"secret"},{pair},
    {artifact:archive}]){
    await assert.rejects(()=>mock.gateway.apply(alice,{...defaultInput(),...extra}),
      /TARGET_APPLY_REQUEST_INVALID/);
  }
  await assert.rejects(()=>mock.gateway.apply(alice,{
    ...defaultInput(),expectedVersion:"v9",
  }),/TARGET_APPLY_VERSION_CONFLICT/);
  await assert.rejects(()=>mock.gateway.apply(alice,{
    ...defaultInput(),expectedName:"customized_mismatch",
  }),/TARGET_APPLY_VERSION_CONFLICT/);
  await assert.rejects(()=>mock.gateway.apply(alice,{
    ...defaultInput(),artifactRevisionId:"a".repeat(64),
  }),/TARGET_APPLY_REVISION_NOT_FOUND/);
  await assert.rejects(()=>mock.gateway.apply(alice,{...defaultInput(),confirmed:false}),
    /TARGET_APPLY_REQUEST_INVALID/);
  assert.deepEqual(mock.writes,[]);
});
test("mock-only adapter refuses real HTTPS DP host before any inventory read",async()=>{
  const mock=mockGateway({badTarget:true});
  await assert.rejects(()=>mock.gateway.apply(alice,defaultInput()),
    /TARGET_APPLY_MOCK_TARGET_REQUIRED/);
  assert.equal(mock.lookups,0);
  assert.deepEqual(mock.writes,[]);
});
test("server approval denial, audit outage and port conflict prevent POST",async()=>{
  for(const variant of [{approve:false},{auditFails:true},{occupiedPort:true},
    {refreshedConflict:true}]){
    const mock=mockGateway(variant);
    await assert.rejects(()=>mock.gateway.apply(alice,defaultInput()),/TARGET_/);
    assert.deepEqual(mock.writes,[]);
    assert.equal(mock.gateway.status(alice,revision).status,"DENIED");
    if(variant.refreshedConflict)assert.equal(mock.catalogs,2);
    if(variant.auditFails)assert.deepEqual(mock.before,["BEFORE:REQUESTED"]);
  }
});
test("uncertain readback is never mistaken for verified DP registration",async()=>{
  const mock=mockGateway({readbackFails:true});
  await assert.rejects(()=>mock.gateway.apply(alice,defaultInput()),
    /TARGET_READBACK_UNVERIFIED/);
  const status=mock.gateway.status(alice,revision);
  assert.equal(status.status,"UNVERIFIED");
  assert.equal(status.realTargetVerified,false);
  assert.deepEqual(mock.writes,["POST"]);
});
test("concurrent same revision is explicitly locked until independent mock GET readback",async()=>{
  let release!:()=>void;
  const hold=new Promise<void>(resolve=>{release=resolve;});
  const mock=mockGateway({waitWrite:async()=>hold});
  const first=mock.gateway.apply(alice,defaultInput());
  for(let i=0;i<100&&mock.writes.length===0;i++)
    await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(mock.writes.length,1);
  await assert.rejects(()=>mock.gateway.apply(alice,defaultInput()),
    /TARGET_APPLY_IN_FLIGHT/);
  assert.equal(mock.gateway.status(alice,revision).status,"IN_PROGRESS");
  release();
  const result=await first;
  assert.equal(result.status,"MOCK_READBACK_VERIFIED");
  assert.equal(mock.gateway.status(alice,revision).status,"MOCK_READBACK_VERIFIED");
});
test("query accepts only exact revision digest and status never reports real target proof",()=>{
  const mock=mockGateway();
  assert.throws(()=>mock.gateway.status(alice,"bad"),/TARGET_APPLY_QUERY_INVALID/);
  assert.equal(mock.gateway.status(alice,revision).realRuntimeParsingVerified,false);
});
