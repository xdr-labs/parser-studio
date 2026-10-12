/**
 * Whole-backend HTTP contract scenario with ONLY public-synthetic fixtures,
 * loopback HTTP and an injected in-memory fake DP/sink. Not a vendor E2E.
 */
import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createHash} from "node:crypto";
import {createBackendServer} from "../src/http.js";
import {compilePair} from "../src/compiler.js";
import {buildArtifactPackage} from "../src/artifact-package.js";
import {instantiateParserTemplate} from "../src/parser-templates.js";
import {ArtifactRevisionHistory} from "../src/artifact-revision-history.js";
import {TargetDeploymentCoordinator,type TargetDeploymentApi} from "../src/target-deployment.js";
import {TargetApplyMockGateway} from "../src/target-apply-bff.js";
import {SyntheticSessionController} from "../src/testlab-session.js";
import {TestLabEvidenceLedger} from "../src/testlab-evidence.js";

const origin="https://offline-only.example.invalid";
const tenant="mock_tenant";
const plan={projectId:"synthetic_flow",slug:"flow_firewall",revision:1,
  port:7123,protocols:["udp" as const]};
const project=instantiateParserTemplate("json",plan);
const pair=compilePair(project);
const artifact=buildArtifactPackage(pair,"1.0.0");
const rev=artifact.manifest.artifactRevisionId;
const alternateProject=instantiateParserTemplate("json",{...plan,revision:2,port:7324});
const alternatePair=compilePair(alternateProject);
const alternateArtifact=buildArtifactPackage(alternatePair,"1.0.1");
const alternateRevision=alternateArtifact.manifest.artifactRevisionId;
const hash=(value:Buffer)=>createHash("sha256").update(value).digest("hex");
const sample={
  format:"json" as const,
  source:'{"timestamp":"2026-01-01T00:00:00Z","src_ip":"192.0.2.8","action":"deny"}',
  seed:47,sequence:0,timestampField:"timestamp",
  variableFields:[{path:"src_ip",kind:"ipv4" as const}],
};
const headers=(owner="alice")=>({
  "content-type":"application/json","x-flow-owner":owner,
});
const send=(base:string,path:string,body:unknown,owner="alice")=>
  fetch(base+path,{method:"POST",headers:headers(owner),body:JSON.stringify(body)});
const read=(base:string,path:string,owner="alice")=>
  fetch(base+path,{headers:headers(owner)});
type Fixture={
  url:string;
  writes:()=>number;
  audits:()=>readonly string[];
  sampleSends:()=>number;
};
async function withFlow(run:(f:Fixture)=>Promise<void>){
  let writes=0;
  let sent=0;
  const audits:string[]=[];
  const liveRows:Array<{name:string;version:string;port:number}>=[];
  const allowed=(req:{headers:Record<string,string|string[]|undefined>})=>
    req.headers["x-flow-owner"]==="alice";
  const local=async(req:{headers:Record<string,string|string[]|undefined>})=>
    allowed(req)?{id:"alice",tenant}:null;
  const api:TargetDeploymentApi={
    listParsers:async()=>[...liveRows],
    listCatalogue:async()=>[{name:"other_example",port:6005}],
    sensorBindings:async()=>({complete:true,ports:[]}),
    localReservations:async()=>({complete:true,ports:[]}),
    writePair:async uploaded=>{
      assert.equal(uploaded.method,"POST");
      assert.equal(uploaded.port,7123);
      assert.equal(uploaded.tenant,tenant);
      assert.deepEqual(uploaded.files.map(f=>f.sha256).sort(),
        Object.values(artifact.manifest.fileHashes).sort());
      writes++;
      liveRows.push({name:uploaded.name,version:uploaded.version,port:uploaded.port});
      return {httpStatus:200};
    },
  };
  const coordinator=new TargetDeploymentCoordinator({
    target:{origin,tenant,sensorIngestPort:7123},permittedOrigins:[origin],
    api,approve:async()=>true,audit:async entry=>{audits.push(entry.phase);},
  });
  const history=new ArtifactRevisionHistory();
  const mockGateway=new TargetApplyMockGateway({
    mode:"MOCK_ONLY",
    authorize:async req=>local(req),
    // No pre-seeded or browser-supplied files: Apply gets the exact pair
    // registered for this authenticated owner through the same BFF store.
    resolveRevision:async(actor,id)=>{
      try{return history.resolveOwnedRevision({
        ownerId:actor.id,tenant:actor.tenant,
      },id);}
      catch{return null;}
    },
    getCoordinator:async()=>coordinator,
    audit:async entry=>{audits.push("HTTP_"+entry.phase);},
  });
  const evidence=new TestLabEvidenceLedger();
  const controller=new SyntheticSessionController({
    evidenceLedger:evidence,approveStart:async()=>true,
    approveRateChange:async()=>true,
    deliver:async()=>{sent++;},
  });
  const server=createBackendServer({
    targetApplyMockGateway:mockGateway,
    artifactRevisionHistory:history,
    authorizeArtifactRevision:async req=>allowed(req)?
      {ownerId:"alice",tenant}:null,
    testLabController:controller,
    authorizeTestLabSession:async req=>allowed(req)?"alice":null,
  });
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{
    const url="http://127.0.0.1:"+(server.address() as AddressInfo).port;
    await run({url,writes:()=>writes,audits:()=>[...audits],sampleSends:()=>sent});
  }finally{
    await new Promise<void>(resolve=>server.close(()=>resolve()));
    controller.stopAll();
  }
}
test("one synthetic user HTTP journey: template, pair, ZIP, revision, fake Apply, replay and report",async()=>{
  await withFlow(async ({url,writes,audits,sampleSends})=>{
    const catalog=await read(url,"/api/v1/parser-pairs/templates");
    assert.equal(catalog.status,200);
    assert.equal((await catalog.json() as any).templates.length,6);
    const inst=await send(url,"/api/v1/parser-pairs/templates/instantiate",{
      templateId:"json",options:plan,
    });
    assert.equal(inst.status,200);
    const draft=await inst.json() as any;
    assert.deepEqual(draft.project,project);
    assert.equal(draft.targetImportVerified,false);
    const valid=await send(url,"/api/v1/parser-pairs/validate",draft.project);
    assert.equal(valid.status,200);
    assert.equal((await valid.json() as any).ok,true);
    const output=await send(url,"/api/v1/parser-pairs/generate",draft.project);
    assert.equal(output.status,200);
    const generated=await output.json() as any;
    assert.deepEqual(generated,pair);
    const bundle=await send(url,"/api/v1/parser-pairs/package",{pair:generated,version:"1.0.0"});
    assert.equal(bundle.status,200);
    const downloaded=Buffer.from(await bundle.arrayBuffer());
    assert.equal(hash(downloaded),artifact.zipSha256);
    assert.equal(bundle.headers.get("x-parser-artifact-revision"),rev);

    const attemptBeforeRegistration=await send(
      url,"/api/v1/parser-pairs/target/apply",{
        artifactRevisionId:rev,expectedName:artifact.manifest.parserName,
        expectedVersion:"1.0.0",approvalId:"owner-allow-123",confirmed:true,
      });
    assert.equal(attemptBeforeRegistration.status,404,
      "an unregistered revision must never be accepted for Apply");
    assert.equal(writes(),0);

    const registered=await send(url,"/api/v1/parser-pairs/revisions/register",{
      pair:generated,version:"1.0.0",
    });
    assert.equal(registered.status,200);
    const meta=await registered.json() as any;
    assert.equal(meta.artifactRevisionId,rev);
    assert.equal(meta.selectedParserPort,7123);
    assert.equal(meta.deploymentPerformed,false);
    const privateZip=await read(url,
      "/api/v1/parser-pairs/revisions/download?artifactRevisionId="+rev);
    assert.equal(privateZip.status,200);
    assert.equal(hash(Buffer.from(await privateZip.arrayBuffer())),artifact.zipSha256);

    const denied=await send(url,"/api/v1/parser-pairs/target/apply",{
      artifactRevisionId:rev,expectedName:artifact.manifest.parserName,
      expectedVersion:"1.0.0",approvalId:"owner-allow-123",confirmed:true,
    },"bob");
    assert.equal(denied.status,403);
    assert.equal(writes(),0);
    const applied=await send(url,"/api/v1/parser-pairs/target/apply",{
      artifactRevisionId:rev,expectedName:artifact.manifest.parserName,
      expectedVersion:"1.0.0",approvalId:"owner-allow-123",confirmed:true,
    });
    assert.equal(applied.status,200);
    const mock=await applied.json() as any;
    assert.equal(mock.status,"MOCK_READBACK_VERIFIED");
    assert.equal(mock.registration.apiReadbackVerified,true);
    assert.equal(mock.registration.targetImportVerified,false);
    assert.equal(mock.realTargetVerified,false);
    assert.equal(writes(),1);
    assert.deepEqual(audits(),
      ["HTTP_BEFORE","BEFORE","AFTER","HTTP_AFTER"]);
    const status=await read(url,
      "/api/v1/parser-pairs/target/apply/status?artifactRevisionId="+rev);
    assert.equal((await status.json() as any).status,"MOCK_READBACK_VERIFIED");

    const started=await send(url,"/api/v1/test-lab/sessions/start",{
      sample,artifactRevisionId:rev,
      approvalId:"owner-session-123",ratePerSecond:5,leaseMs:1500,maxEvents:3,
    });
    assert.equal(started.status,200);
    const {runId}=await started.json() as {runId:string};
    await new Promise(resolve=>setTimeout(resolve,260));
    const report=await read(url,
      "/api/v1/test-lab/sessions/evidence?runId="+runId);
    assert.equal(report.status,200);
    const observed=await report.json() as any;
    assert.equal(observed.artifactRevisionId,rev);
    assert.ok(observed.counts.generated>0);
    assert.equal(observed.counts.generated,observed.counts.sinkAccepted);
    assert.equal(observed.counts.sensorObserved,0);
    assert.equal(observed.counts.dpIndexed,0);
    assert.equal(observed.liveE2eVerified,false);
    assert.ok(sampleSends()>0,"mock sink accepts only synthetic local callbacks");
    assert.equal(JSON.stringify(observed).includes("192.0.2.8"),false);
    assert.equal((await read(url,
      "/api/v1/test-lab/sessions/evidence?runId="+runId,"bob")).status,403);
    const stop=await send(url,"/api/v1/test-lab/sessions/stop",{runId});
    assert.equal(stop.status,200);
    assert.equal((await stop.json() as any).state,"STOPPED");
  });
});
test("changing the selected CONF port changes both hashes and blocks fake Apply to an older sensor port",async()=>{
  await withFlow(async ({url,writes})=>{
    const updated={...plan,revision:2,port:7324};
    const p2=await (await send(url,"/api/v1/parser-pairs/templates/instantiate",
      {templateId:"json",options:updated})).json() as any;
    const pair2=await (await send(url,"/api/v1/parser-pairs/generate",p2.project)).json() as any;
    const reg=await send(url,"/api/v1/parser-pairs/revisions/register",{
      pair:pair2,version:"1.0.1",
    });
    assert.equal(reg.status,200);
    const data=await reg.json() as any;
    assert.notEqual(data.artifactRevisionId,rev);
    assert.equal(data.selectedParserPort,7324);
    for(const [name,previousHash] of Object.entries(artifact.manifest.fileHashes)){
      assert.notEqual(data.fileHashes[name],previousHash,
        "both Ruby and CONF must be regenerated when source port changes");
    }
    const zip=await read(url,
      "/api/v1/parser-pairs/revisions/download?artifactRevisionId="+data.artifactRevisionId);
    assert.equal(zip.status,200);
    assert.notEqual(hash(Buffer.from(await zip.arrayBuffer())),artifact.zipSha256);
    const invalid=await send(url,"/api/v1/parser-pairs/target/apply",{
      artifactRevisionId:data.artifactRevisionId,
      expectedName:data.parserName,expectedVersion:"1.0.1",
      approvalId:"owner-allow-123",confirmed:true,
    });
    assert.equal(invalid.status,409,
      "different destination port must stop Apply before mock DP inventory");
    assert.equal((await invalid.json() as any).error,"TARGET_SENSOR_CONF_PORT_MISMATCH");
    assert.equal(writes(),0);
  });
});
