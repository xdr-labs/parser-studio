import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createMainlineAuthoringServer,isMainlineAuthoringRoute} from "../src/mainline-authoring-server.js";
import {sampleProject} from "./fixture.js";

async function withServer(run:(base:string)=>Promise<void>):Promise<void>{
  const server=createMainlineAuthoringServer();
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{
    await run("http://127.0.0.1:"+(server.address() as AddressInfo).port);
  }finally{
    await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
  }
}
function post(base:string,path:string,body:unknown):Promise<Response>{
  return fetch(base+path,{
    method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify(body),
  });
}

test("shipping backend accepts only true offline authoring HTTP methods",async()=>{
  assert.equal(isMainlineAuthoringRoute("/api/v1/parser-pairs/generate","POST"),true);
  assert.equal(isMainlineAuthoringRoute("/api/v1/parser-pairs/recipe/v0.2/generate","POST"),true);
  assert.equal(isMainlineAuthoringRoute("/api/v1/parser-pairs/generate","GET"),false);
  assert.equal(isMainlineAuthoringRoute("/api/v1/test-lab/sessions/start","POST"),false);
  assert.equal(isMainlineAuthoringRoute("/api/v1/parser-pairs/target/apply","POST"),false);
  // Ordinary objects inherit property names outside their explicit route
  // keys. Those names must fail closed instead of throwing from .includes().
  for(const path of ["__proto__","constructor","toString","valueOf",
    "/api/v1/parser-pairs/__proto__","/api/v1/parser-pairs/generate/"]){
    assert.doesNotThrow(()=>isMainlineAuthoringRoute(path,"POST"));
    assert.equal(isMainlineAuthoringRoute(path,"POST"),false);
  }

  await withServer(async base=>{
    for(const path of ["/health","/api/v1/parser-pairs/schema",
      "/api/v1/parser-pairs/capabilities","/api/v1/parser-pairs/recipe/v0.2/capabilities"]){
      const result=await fetch(base+path);
      assert.equal(result.status,200,path);
    }
    // Never advertise capabilities that the actual shipping HTTP
    // entrypoint deliberately blocks.
    const capabilityResponse=await fetch(base+"/api/v1/parser-pairs/capabilities");
    assert.equal(capabilityResponse.headers.get("cache-control"),"no-store");
    const advertised=await capabilityResponse.json() as Record<string,unknown>;
    assert.equal("testLab" in advertised,false);
    const authoring=advertised["authoring"] as Record<string,unknown>;
    assert.equal(authoring["syntheticTemplateHttpAvailable"],false);
    assert.equal(authoring["deterministicNameOnlyMappingHttpAvailable"],false);
    const downloads=advertised["downloads"] as Record<string,unknown>;
    assert.deepEqual(Object.keys(downloads).sort(),[
      "autoDeploys","exactArtifactRevision","individualGeneratedFiles",
      "requiresApiKey","requiresDpConnection","zipWithManifest",
    ]);
    assert.equal(downloads["autoDeploys"],false);
    assert.equal("ownedOfflineRevisionHistoryOptIn" in downloads,false);
    const verification=advertised["verification"] as Record<string,unknown>;
    assert.equal(verification["targetImportVerified"],false);
    assert.equal("nativeCapabilityManifestHttpOptInAvailable" in verification,false);
    const imported=advertised["import"] as Record<string,unknown>;
    assert.equal("redactedImportLossReportHttpAvailable" in imported,false);

    const verified=await post(base,"/api/v1/parser-pairs/validate",sampleProject());
    assert.equal(verified.status,200);
    assert.equal(((await verified.json()) as {ok:boolean}).ok,true);
    const generated=await post(base,"/api/v1/parser-pairs/generate",sampleProject());
    assert.equal(generated.status,200);
    const pair=await generated.json() as {
      files:unknown[];manifest:{status:string;targetImportVerified:boolean};
    };
    assert.equal(pair.files.length,2);
    assert.equal(pair.manifest.status,"DRAFT");
    assert.equal(pair.manifest.targetImportVerified,false);
  });
});

test("the historical server CLI cannot bypass the shipping authoring-only route boundary",async()=>{
  const source=await import("node:fs/promises");
  const path=await import("node:path");
  const code=await source.readFile(path.resolve("src/server.ts"),"utf8");
  assert.match(code,/createMainlineAuthoringServer\(\)\.listen\(/);
  assert.doesNotMatch(code,/createBackendServer\(\)\.listen\(/);
});

test("target, Test Lab, revision, optional AI and Interflow routes remain unreachable",async()=>{
  await withServer(async base=>{
    const raw="SHOULD_NEVER_APPEAR_12345";
    const denied=[
      ["POST","/api/v1/test-lab/sessions/start"],
      ["GET","/api/v1/test-lab/sessions/evidence-summary?runId=test_run_"+("a".repeat(32))],
      ["GET","/api/v1/test-lab/interflow/search"],
      ["POST","/api/v1/parser-pairs/target/apply"],
      ["GET","/api/v1/parser-pairs/target/apply/status?artifactRevisionId="+("a".repeat(64))],
      ["POST","/api/v1/stellar/legacy/prepare"],
      ["GET","/api/v1/parser-pairs/revisions/list?projectId=draft"],
      ["POST","/api/v1/parser-pairs/ai/v0.1/review"],
      ["POST","/api/v1/parser-pairs/recipe/v0.2/native-verify"],
      ["GET","/api/v1/parser-pairs/generate"],
    ] as const;
    for(const [method,path] of denied){
      const response=await fetch(base+path,{
        method, ...(method==="POST"?{headers:{"content-type":"application/json"},
          body:JSON.stringify({source:raw})}:{}),
      });
      assert.equal(response.status,404,method+" "+path);
      const body=await response.text();
      assert.equal(body.includes(raw),false);
      assert.deepEqual(JSON.parse(body),{error:"AUTHORING_ONLY_ROUTE_NOT_AVAILABLE"});
    }
  });
});
