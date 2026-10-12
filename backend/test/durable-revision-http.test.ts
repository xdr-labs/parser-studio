import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,rmSync,readFileSync,writeFileSync,unlinkSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";
import {DurableArtifactRevisionHistory} from "../src/durable-revision-history.js";
import {TargetApplyMockGateway} from "../src/target-apply-bff.js";
import {TargetDeploymentCoordinator,type TargetDeploymentApi} from "../src/target-deployment.js";

const tenant="tenant_a";
const ownerId="synthetic-alice";
const origin="https://isolated-durable-target.example.invalid";
const actor={ownerId,tenant};
const apiPath="/api/v1/parser-pairs/";
const use=async(fn:(file:string)=>Promise<void>)=>{
  const dir=mkdtempSync(join(tmpdir(),"parserstudio-durable-http-"));
  try{await fn(join(dir,"artifact-revisions.json"));}
  finally{rmSync(dir,{recursive:true,force:true});}
};
const pair=()=>compilePair(sampleProject());
function makeGateway(history:DurableArtifactRevisionHistory){
  const writes:string[]=[];
  const rows:Array<{name:string;version:string;port:number}>=[];
  const api:TargetDeploymentApi={
    listParsers:async()=>[...rows],
    listCatalogue:async()=>[{name:"reserved",port:5800}],
    sensorBindings:async()=>({complete:true,ports:[]}),
    localReservations:async()=>({complete:true,ports:[]}),
    writePair:async request=>{
      assert.equal(request.tenant,tenant);
      writes.push(request.method);
      rows.push({name:request.name,version:request.version,port:request.port});
      return {httpStatus:200};
    },
  };
  const coordinator=new TargetDeploymentCoordinator({
    target:{origin,tenant,sensorIngestPort:7123},permittedOrigins:[origin],api,
    approve:async()=>true,audit:async()=>{},
  });
  const gateway=new TargetApplyMockGateway({
    mode:"MOCK_ONLY",
    authorize:async req=>req.headers["x-synthetic-principal"]===ownerId?
      {id:ownerId,tenant}:null,
    resolveRevision:async(requester,id)=>{
      try{return history.resolveOwnedRevision({ownerId:requester.id,tenant:requester.tenant},id);}
      catch{return null;}
    },
    getCoordinator:async()=>coordinator,
    audit:async event=>{history.recordMockApplyAudit(event);},
  });
  return {gateway,writes};
}
async function withHttp(history:DurableArtifactRevisionHistory,fn:(base:string)=>Promise<void>,
  gateway?:TargetApplyMockGateway){
  const server=createBackendServer({
    artifactRevisionHistory:history,
    authorizeArtifactRevision:async req=>req.headers["x-synthetic-principal"]===ownerId?actor:null,
    targetApplyMockGateway:gateway,
  });
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{await fn("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}
const request=(base:string,route:string,data:unknown)=>{
  return fetch(base+apiPath+route,{method:"POST",
    headers:{"content-type":"application/json","x-synthetic-principal":ownerId},
    body:JSON.stringify(data)});
};

test("HTTP register/list, restart and MOCK-only Apply use durable owner-scoped audit",async()=>{
  await use(async file=>{
    const history=new DurableArtifactRevisionHistory(file);
    const mock=makeGateway(history);
    let artifactRevisionId="",zipSha256="",parserName="";
    await withHttp(history,async base=>{
      const registered=await request(base,"revisions/register",{pair:pair(),version:"1.0.0"});
      assert.equal(registered.status,200);
      const artifact=await registered.json() as any;
      ({artifactRevisionId,zipSha256}=artifact);
      parserName=artifact.parserName;
      const caps=await (await fetch(base+apiPath+"capabilities")).json() as any;
      assert.equal(caps.downloads.revisionHistoryDurableAcrossRestart,true);
      const list=await fetch(base+apiPath+"revisions/list?projectId=synthetic-fixture",{
        headers:{"x-synthetic-principal":ownerId}});
      assert.equal(list.status,200);
      assert.equal((await list.json() as any).persistent,true);
      const application=await request(base,"target/apply",{
        artifactRevisionId,approvalId:"synthetic-approve-123",
        expectedName:parserName,expectedVersion:"1.0.0",confirmed:true});
      assert.equal(application.status,200);
      assert.equal((await application.json() as any).status,"MOCK_READBACK_VERIFIED");
      assert.deepEqual(mock.writes,["POST"]);
    },mock.gateway);
    const reboot=new DurableArtifactRevisionHistory(file);
    const audit=reboot.listMockApplyAudit(actor);
    assert.deepEqual(audit.map(a=>a.phase),["BEFORE","AFTER"]);
    assert.deepEqual(audit.map(a=>a.status),["REQUESTED","MOCK_READBACK_VERIFIED"]);
    assert.equal(reboot.download(actor,artifactRevisionId).zipSha256,zipSha256);
    assert.equal(audit.every(event=>
      Object.keys(event).sort().join(",")==="actorId,artifactRevisionId,at,phase,status,tenant"),true);
    assert.equal(JSON.stringify(audit).includes("synthetic-approve-123"),false);
  });
});

test("corrupt persistent revision fails HTTP closed and never permits mock target writes",async()=>{
  await use(async file=>{
    const history=new DurableArtifactRevisionHistory(file);
    const id=history.register(actor,pair(),"1.0.0").artifactRevisionId;
    const mock=makeGateway(history);
    const text=readFileSync(file,"utf8");
    writeFileSync(file,text.replace("synthetic-fixture","forged-fixture"),{mode:0o600});
    await withHttp(history,async base=>{
      const list=await fetch(base+apiPath+"revisions/list?projectId=synthetic-fixture",{
        headers:{"x-synthetic-principal":ownerId}});
      assert.equal(list.status,503);
      assert.equal((await list.json() as any).error,"REVISION_STORE_INTEGRITY");
      const applied=await request(base,"target/apply",{
        artifactRevisionId:id,approvalId:"synthetic-approve-123",
        expectedName:"customized_sample_firewall",expectedVersion:"1.0.0",confirmed:true});
      assert.notEqual(applied.status,200);
      assert.deepEqual(mock.writes,[]);
    },mock.gateway);
  });
});

test("pre-Apply durable audit lock failure denies fake write and leaves metadata unchanged",async()=>{
  await use(async file=>{
    const history=new DurableArtifactRevisionHistory(file);
    const artifact=history.register(actor,pair(),"1.0.0");
    const mock=makeGateway(history);
    const lock=join(file,"..",".artifact-revisions.lock");
    writeFileSync(lock,"untrusted",{mode:0o600});
    try{
      await withHttp(history,async base=>{
        const applied=await request(base,"target/apply",{
          artifactRevisionId:artifact.artifactRevisionId,approvalId:"synthetic-approve-123",
          expectedName:artifact.parserName,expectedVersion:"1.0.0",confirmed:true});
        assert.equal(applied.status,503);
        assert.equal((await applied.json() as any).error,"TARGET_APPLY_AUDIT_UNAVAILABLE");
        assert.deepEqual(mock.writes,[]);
      },mock.gateway);
    }finally{unlinkSync(lock);}
    assert.deepEqual(new DurableArtifactRevisionHistory(file).listMockApplyAudit(actor),[]);
  });
});
