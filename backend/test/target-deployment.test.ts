import test from "node:test";
import assert from "node:assert/strict";
import {compilePair} from "../src/compiler.js";
import {buildArtifactPackage} from "../src/artifact-package.js";
import {sampleProject} from "./fixture.js";
import {
  TargetDeploymentCoordinator,validateDpTarget,
  type TargetDeploymentApi,type TargetDeploymentAudit,
  type TargetOperationIntent,
} from "../src/target-deployment.js";

const tenant="synthetic_tenant";
const target="https://dp-test.example.invalid";
const pair=()=>compilePair(sampleProject());
const bundle=()=>buildArtifactPackage(pair(),"1.0.0");
function setup(settings?:{
  approval?:(intent:TargetOperationIntent)=>Promise<boolean>;
  audit?:(record:TargetDeploymentAudit)=>Promise<void>;
  failWrite?:boolean;
  uncertainReadback?:boolean;
  occupiedPort?:boolean;
  unknownSensor?:boolean;
}){
  const rows:Array<{name:string;version:string;port:number}>=[];
  const writes:string[]=[];
  const logs:TargetDeploymentAudit[]=[];
  const api:TargetDeploymentApi={
    listParsers:async()=>settings?.uncertainReadback&&writes.length?[]:[...rows],
    listCatalogue:async()=>settings?.occupiedPort?[{port:7123,name:"system_default"}]:[{port:6001,name:"system_default"}],
    sensorBindings:async()=>settings?.unknownSensor?
      {complete:false,ports:[]}:{complete:true,ports:[20010]},
    localReservations:async()=>({complete:true,ports:[20020]}),
    writePair:async request=>{
      writes.push(request.method);
      if(settings?.failWrite)throw Error("SECRET_VENDOR_RESPONSE_NEVER_ECHO");
      assert.equal(request.name,"customized_sample_firewall");
      assert.equal(request.files.length,2);
      assert.deepEqual(request.files.map(f=>f.filename).sort(),
        ["customized_sample_firewall","customized_sample_firewall.conf"].sort());
      assert.equal(request.files.find(f=>f.filename.endsWith(".conf"))?.sha256,
        bundle().manifest.fileHashes["customized_sample_firewall.conf"]);
      rows.push({name:request.name,version:request.version,port:request.port});
      return {httpStatus:200};
    },
  };
  const coordinator=new TargetDeploymentCoordinator({
    target:{origin:target,tenant},
    permittedOrigins:[target],
    api,
    approve:settings?.approval??(async()=>true),
    audit:settings?.audit??(async record=>{logs.push(record);}),
  });
  return {coordinator,writes,logs,rows};
}

test("HTTPS DP target normalization rejects redirect/cross-site URL/embedded credentials",()=>{
  assert.equal(validateDpTarget(target,[target]).origin,target);
  for(const bad of [
    "http://dp-test.example.invalid",
    "https://dp-test.example.invalid/legacy",
    "https://dp-test.example.invalid?redirect=evil",
    "https://user:secret@dp-test.example.invalid",
    "https://evil.example.invalid",
    "https://dp-test.example.invalid.evil.test",
    "https://127.0.0.1","https://[::1]",
  ])assert.throws(()=>validateDpTarget(bad,[target]),/TARGET_ORIGIN_/);
});

test("exact generated artifact revision applies only to authorized origin+tenant with readback",async()=>{
  const {coordinator,writes,logs,rows}=setup();
  const archive=bundle();
  const outcome=await coordinator.create({
    artifact:archive, pair:pair(),expectedRevisionId:archive.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  });
  assert.deepEqual(writes,["POST"]);
  assert.equal(rows.length,1);
  assert.equal(outcome.registration.status,"API_REGISTERED_READBACK");
  assert.equal(outcome.registration.apiReadbackVerified,true);
  assert.equal(outcome.registration.realRuntimeParsingVerified,false);
  assert.equal(outcome.registration.sensorReadyVerified,false);
  assert.equal(outcome.registration.targetImportVerified,false);
  assert.equal(outcome.artifactRevisionId,archive.manifest.artifactRevisionId);
  assert.equal(outcome.fileHashes["customized_sample_firewall"],
    archive.manifest.fileHashes["customized_sample_firewall"]);
  assert.deepEqual(logs.map(e=>e.phase),["BEFORE","AFTER"]);
  assert.equal(JSON.stringify(outcome).includes("Base64.strict_decode64"),false);
});

test("port collisions, incomplete sensor evidence, name duplicates and stale artifact hash fail before POST",async()=>{
  for(const variant of [
    {occupiedPort:true},
    {unknownSensor:true},
  ]){
    const {coordinator,writes}=setup(variant);
    const artifact=bundle();
    await assert.rejects(()=>coordinator.create({
      artifact,pair:pair(),expectedRevisionId:artifact.manifest.artifactRevisionId,
      confirmation:{approved:true,approvalId:"owner-explicit-1",
        targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
    }),/TARGET_(?:PORT_CONFLICT|SENSOR_EVIDENCE_INCOMPLETE)/);
    assert.equal(writes.length,0);
  }
  const {coordinator,writes}=setup();
  const artifact=bundle();
  await assert.rejects(()=>coordinator.create({
    artifact,pair:pair(),expectedRevisionId:"1".repeat(64),
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  }),/TARGET_ARTIFACT_REVISION_CONFLICT/);
  const moved=sampleProject();moved.receiver.port=25000;
  await assert.rejects(()=>coordinator.create({
    artifact,pair:compilePair(moved),expectedRevisionId:artifact.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  }),/TARGET_ARTIFACT_/);
  assert.equal(writes.length,0);
});

test("backend-approval and before-write audit are compulsory; no silent retry on network failure",async()=>{
  const {coordinator,writes}=setup({approval:async()=>false});
  const artifact=bundle();
  await assert.rejects(()=>coordinator.create({
    artifact,pair:pair(),expectedRevisionId:artifact.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  }),/TARGET_APPROVAL_DENIED/);
  assert.equal(writes.length,0);

  const failing=setup({failWrite:true});
  await assert.rejects(()=>failing.coordinator.create({
    artifact,pair:pair(),expectedRevisionId:artifact.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  }),(error:unknown)=>error instanceof Error&&
    error.message==="TARGET_WRITE_UNCERTAIN");
  assert.deepEqual(failing.writes,["POST"]);
  assert.equal(JSON.stringify(failing.logs).includes("SECRET_VENDOR_RESPONSE"),false);
  assert.deepEqual(failing.logs.map(x=>x.phase),["BEFORE","FAILED"]);
});

test("unconfirmed, mismatched target, uncertain GET readback remain unverified",async()=>{
  const a=bundle(),s=setup({uncertainReadback:true});
  for(const update of [
    {approved:false},
    {targetOrigin:"https://different.example.invalid"},
    {tenant:"other_tenant"},
  ]){
    await assert.rejects(()=>s.coordinator.create({
      artifact:a,pair:pair(),expectedRevisionId:a.manifest.artifactRevisionId,
      confirmation:{approved:true,approvalId:"owner-explicit-1",
        targetOrigin:target,tenant,expectedName:"customized_sample_firewall",...update},
    }),/TARGET_/);
  }
  assert.equal(s.writes.length,0);
  await assert.rejects(()=>s.coordinator.create({
    artifact:a,pair:pair(),expectedRevisionId:a.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  }),/TARGET_READBACK_UNVERIFIED/);
  assert.deepEqual(s.writes,["POST"]);
  assert.deepEqual(s.logs.map(x=>x.phase),["BEFORE","FAILED"]);
});

test("two concurrent creates of the same tenant/name fail the second before write",async()=>{
  let release=()=>{};
  const gate=new Promise<void>(resolve=>{release=resolve;});
  let approvals=0;
  const {coordinator,writes}=setup({approval:async()=>{
    approvals++;await gate;return true;
  }});
  const artifact=bundle(),request={
    artifact,pair:pair(),expectedRevisionId:artifact.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  };
  const first=coordinator.create(request);
  const second=coordinator.create(request);
  await assert.rejects(second,/TARGET_APPLY_IN_FLIGHT/);
  assert.equal(approvals,1);
  release();
  const result=await first;
  assert.equal(result.registration.apiReadbackVerified,true);
  assert.deepEqual(writes,["POST"]);
});

test("fresh port inventory changes immediately before upload fail closed",async()=>{
  let lookups=0,writes=0;
  const api:TargetDeploymentApi={
    listParsers:async()=>[],
    listCatalogue:async()=>{
      lookups++;
      return lookups>1?[{name:"builtin_parser",port:7123}]:[];
    },
    sensorBindings:async()=>({complete:true,ports:[]}),
    localReservations:async()=>({complete:true,ports:[]}),
    writePair:async()=>{writes++;return {httpStatus:200};},
  };
  const runner=new TargetDeploymentCoordinator({
    target:{origin:target,tenant},permittedOrigins:[target],api,
    approve:async()=>true,audit:async()=>{},
  });
  const artifact=bundle();
  await assert.rejects(()=>runner.create({
    artifact,pair:pair(),expectedRevisionId:artifact.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  }),/TARGET_PORT_CONFLICT/);
  assert.equal(writes,0);
  assert.equal(lookups,2);
});

test("deployment failures never mutate the independent offline download archive",async()=>{
  const pkg=bundle(),zip=Buffer.from(pkg.zip);
  const {coordinator}=setup({failWrite:true});
  await assert.rejects(()=>coordinator.create({
    artifact:pkg,pair:pair(),expectedRevisionId:pkg.manifest.artifactRevisionId,
    confirmation:{approved:true,approvalId:"owner-explicit-1",
      targetOrigin:target,tenant,expectedName:"customized_sample_firewall"},
  }),/TARGET_WRITE_UNCERTAIN/);
  assert.ok(zip.equals(pkg.zip));
  assert.ok(zip.equals(buildArtifactPackage(pair(),"1.0.0").zip));
});
