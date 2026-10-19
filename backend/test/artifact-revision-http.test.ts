import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {ArtifactRevisionHistory} from "../src/artifact-revision-history.js";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";

const basePath="/api/v1/parser-pairs/revisions";
const actorHeaders=(name="alice")=>({
  "content-type":"application/json",
  "x-synthetic-principal":name,
});
const request=(base:string,route:string,body:unknown,owner="alice")=>
  fetch(base+basePath+"/"+route,{
    method:"POST",headers:actorHeaders(owner),body:JSON.stringify(body),
  });
const get=(base:string,route:string,query:string,owner="alice")=>
  fetch(base+basePath+"/"+route+query,{headers:actorHeaders(owner)});
const digest=(buf:Buffer)=>createHash("sha256").update(buf).digest("hex");
async function withServer(configured:boolean,run:(base:string)=>Promise<void>){
  const history=configured?new ArtifactRevisionHistory():undefined;
  const server=createBackendServer(configured?{
    artifactRevisionHistory:history,
    authorizeArtifactRevision:async req=>{
      const principal=req.headers["x-synthetic-principal"];
      return principal==="alice"?{ownerId:"alice",tenant:"test_tenant"}:
        principal==="bob"?{ownerId:"bob",tenant:"test_tenant"}:
        principal==="tenant2"?{ownerId:"alice",tenant:"tenant_two"}:null;
    },
  }:{});
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{await run("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}
const pair=(port=7123,revision=1)=>{
  const p=sampleProject();
  p.receiver.port=port;p.revision=revision;
  return compilePair(p);
};
test("default backend has no revision persistence or download route",async()=>{
  await withServer(false,async base=>{
    const response=await request(base,"register",{pair:pair(),version:"1.0.0"});
    assert.equal(response.status,403);
    assert.equal((await response.json() as any).error,"REVISION_HISTORY_DISABLED");
    const caps=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(caps.downloads.ownedOfflineRevisionHistoryOptIn,true);
    assert.equal(caps.downloads.ownedOfflineRevisionHttpAvailableWhenInjected,true);
    assert.equal(caps.downloads.revisionRestorePreviewNeverWritesTarget,true);
    assert.equal(caps.downloads.revisionHistoryDurableAcrossRestart,false);
    const list=await get(base,"list","?projectId=synthetic-fixture");
    assert.equal(list.status,403);
  });
});
test("authenticated in-memory register/list/download returns exact ZIP only for owner",async()=>{
  await withServer(true,async base=>{
    const response=await request(base,"register",{pair:pair(),version:"1.0.0"});
    assert.equal(response.status,200);
    const created=await response.json() as any;
    assert.match(created.artifactRevisionId,/^[a-f0-9]{64}$/);
    assert.equal(created.deploymentPerformed,false);
    const listed=await get(base,"list","?projectId=synthetic-fixture");
    assert.equal(listed.status,200);
    const details=await listed.json() as any;
    assert.equal(details.revisions.length,1);
    assert.equal(details.revisions[0].artifactRevisionId,created.artifactRevisionId);
    assert.equal(JSON.stringify(details).includes("Base64.strict_decode64"),false);
    const zip=await get(base,"download","?artifactRevisionId="+created.artifactRevisionId);
    assert.equal(zip.status,200);
    assert.equal(zip.headers.get("content-type"),"application/zip");
    assert.equal(zip.headers.get("cache-control"),"no-store");
    const bytes=Buffer.from(await zip.arrayBuffer());
    assert.equal(digest(bytes),created.zipSha256);
    assert.equal(zip.headers.get("x-parser-zip-sha256"),digest(bytes));
    assert.equal((await get(base,"download","?artifactRevisionId="+created.artifactRevisionId,"bob")).status,404);
    assert.equal((await get(base,"list","?projectId=synthetic-fixture","bob").then(r=>r.json()) as any).revisions.length,0);
    assert.equal((await request(base,"register",{pair:pair(),version:"1.0.0"},"bob")).status,200);
    assert.equal((await request(base,"register",{pair:pair(),version:"1.0.0"},"tenant2")).status,200);
  });
});
test("owned checksum diff and restore preview do not mutate current revision or target",async()=>{
  await withServer(true,async base=>{
    const a=await (await request(base,"register",{pair:pair(),version:"1.0.0"})).json() as any;
    const b=await (await request(base,"register",{pair:pair(7350,2),version:"1.0.1"})).json() as any;
    const compared=await request(base,"diff",{
      fromRevisionId:a.artifactRevisionId,toRevisionId:b.artifactRevisionId});
    assert.equal(compared.status,200);
    const changes=await compared.json() as any;
    assert.equal(changes.selectedParserPort.from,7123);
    assert.equal(changes.selectedParserPort.to,7350);
    assert.equal(changes.files.length,2);
    assert.equal(changes.appliesToDp,false);
    const restored=await request(base,"restore-preview",{
      previousRevisionId:a.artifactRevisionId,expectedCurrentRevisionId:b.artifactRevisionId});
    assert.equal(restored.status,200);
    assert.equal(restored.headers.get("x-parser-restore-status"),"OFFLINE_RESTORE_PREVIEW");
    assert.equal(digest(Buffer.from(await restored.arrayBuffer())),a.zipSha256);
    const old=await request(base,"restore-preview",{
      previousRevisionId:a.artifactRevisionId,expectedCurrentRevisionId:a.artifactRevisionId});
    assert.equal(old.status,409);
    const list=await (await get(base,"list","?projectId=synthetic-fixture")).json() as any;
    assert.deepEqual(list.revisions.map((r:any)=>r.artifactRevisionId),
      [a.artifactRevisionId,b.artifactRevisionId]);
  });
});
test("per-route owner auth, exact input contracts and request size fail closed",async()=>{
  await withServer(true,async base=>{
    const unknown=await request(base,"register",{pair:pair(),version:"1.0.0"},"nobody");
    assert.equal(unknown.status,403);
    const noContent=await fetch(base+basePath+"/register",{method:"POST",
      headers:{"content-type":"text/plain","x-synthetic-principal":"alice"},
      body:"secret"});
    assert.equal(noContent.status,415);
    const injected=await request(base,"register",{
      pair:pair(),version:"1.0.0",dpUrl:"https://test.example.invalid"});
    assert.equal(injected.status,422);
    const huge=await request(base,"register",{pair:pair(),
      version:"1.0.0",raw:"x".repeat(3000000)});
    assert.equal(huge.status,413);
    const method=await get(base,"register","");
    assert.equal(method.status,405);
    const malformed=await get(base,"download","?artifactRevisionId=short");
    assert.equal(malformed.status,422);
    const duplicates=await get(base,"list","?projectId=synthetic-fixture&projectId=synthetic-fixture");
    assert.equal(duplicates.status,422);
    const unknownQuery=await get(base,"list","?projectId=synthetic-fixture&tenant=other");
    assert.equal(unknownQuery.status,422);
  });
});
