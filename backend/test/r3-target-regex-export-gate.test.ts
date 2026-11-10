import test from "node:test";
import assert from "node:assert/strict";
import type {AddressInfo} from "node:net";
import {createMainlineAuthoringServer} from "../src/mainline-authoring-server.js";
import {requiresUnavailableTargetRegex,pairIncludesUnavailableTargetRegex,
  TARGET_REGEX_EXPORT_ERROR} from "../src/target-runtime-export.js";
import {recipeFromLegacyProject} from "../src/parser-recipe-v02.js";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";

function regexProject(format:"regex"|"syslog_rfc3164"|"syslog_rfc5424"){
  const p=sampleProject();
  p.extraction=format==="regex"?
    {format:"regex" as const,pattern:"^(?<action>ALLOW)$"}:
    {format,syslogBodyFormat:"regex" as const,pattern:"^(?<action>ALLOW)$"};
  return p;
}
async function runWithServer(fn:(base:string)=>Promise<void>){
  const server=createMainlineAuthoringServer();
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{await fn("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>((resolve,reject)=>server.close(err=>err?reject(err):resolve()));}
}
function post(base:string,path:string,body:unknown){
  return fetch(base+path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
}
test("shipped Ruby2.4 target profile disables Regex export, keeps local review and runtime truth",async()=>{
  await runWithServer(async base=>{
    const capability=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as {
      authoring:{boundedRegexNamedCaptureSubset:boolean};
      downloads:{targetRuntimeProfile:{profile:string;regexPreviewSupported:boolean;regexExportSupported:boolean;targetImportVerified:boolean}};
    };
    assert.equal(capability.authoring.boundedRegexNamedCaptureSubset,true);
    assert.deepEqual(capability.downloads.targetRuntimeProfile,{
      profile:"stellar70-observed-ruby24",ruby:"2.4.9",fluentd:"1.7.4",
      regexPreviewSupported:true,regexExportSupported:false,targetImportVerified:false,
    });
    const recipeCaps=await (await fetch(base+"/api/v1/parser-pairs/recipe/v0.2/capabilities")).json() as {
      targetRuntimeProfile:{regexExportSupported:boolean};
    };
    assert.equal(recipeCaps.targetRuntimeProfile.regexExportSupported,false);
  });
});
test("standalone and RFC3164/5424 Regex validation is browser-safe, never exported",async()=>{
  await runWithServer(async base=>{
    for(const format of ["regex","syslog_rfc3164","syslog_rfc5424"] as const){
      const project=regexProject(format);
      assert.equal(requiresUnavailableTargetRegex(project.extraction),true);
      const validate=await post(base,"/api/v1/parser-pairs/validate",project);
      assert.equal(validate.status,200,format);
      const validation=await validate.json() as {ok:boolean;targetExportSupported:boolean};
      assert.equal(validation.ok,true);
      assert.equal(validation.targetExportSupported,false);
      const generate=await post(base,"/api/v1/parser-pairs/generate",project);
      assert.equal(generate.status,422,format);
      const refusal=await generate.json() as {error:string;issues:Array<{code:string;message:string}>};
      assert.equal(refusal.error,TARGET_REGEX_EXPORT_ERROR);
      assert.deepEqual(refusal.issues.map(x=>x.code),[TARGET_REGEX_EXPORT_ERROR]);
      assert.match(refusal.issues[0]!.message,/Ruby 2\.4\.9/);
      // Even a genuine local compiled DRAFT with internally matching hashes
      // cannot be re-packaged through the shipping endpoint.
      const compiled=compilePair(project);
      assert.equal(pairIncludesUnavailableTargetRegex(compiled),true);
      const archive=await post(base,"/api/v1/parser-pairs/package",{
        pair:compiled,version:"1.0.0",
      });
      assert.equal(archive.status,422,format);
      assert.equal((await archive.json() as {error:string}).error,TARGET_REGEX_EXPORT_ERROR);
    }
  });
});
test("v0.2 ChatGPT-assisted recipe validate/generate are both refused for Ruby2.4 Regex",async()=>{
  await runWithServer(async base=>{
    for(const format of ["regex","syslog_rfc5424"] as const){
      const project=regexProject(format);
      project.projectId="draft-synthetic_recipe";
      project.classification.rules=[];
      const recipe=recipeFromLegacyProject(project,"b".repeat(64),2);
      const req={legacyProject:project,recipe};
      for(const route of ["validate","generate"]){
        const response=await post(base,"/api/v1/parser-pairs/recipe/v0.2/"+route,req);
        assert.equal(response.status,422,format+" "+route);
        const json=await response.json() as {error:string;issues:Array<{code:string}>};
        assert.equal(json.error,"UNSUPPORTED_RECIPE_V02");
        assert.equal(json.issues[0]?.code,TARGET_REGEX_EXPORT_ERROR);
      }
    }
  });
});
test("non-Regex JSON/KV and RFC5424 body remain downloadable, no false target verified claim",async()=>{
  await runWithServer(async base=>{
    for(const extraction of [
      {format:"json" as const},{format:"kv" as const},
      {format:"syslog_rfc5424" as const,syslogBodyFormat:"kv" as const},
    ]){
      const p=sampleProject();p.extraction=extraction;
      const response=await post(base,"/api/v1/parser-pairs/generate",p);
      assert.equal(response.status,200,JSON.stringify(extraction));
      const pair=await response.json() as {
        files:unknown[];manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean};
      };
      assert.equal(pair.files.length,2);
      assert.equal(pair.manifest.status,"DRAFT");
      assert.equal(pair.manifest.engineVerified,false);
      assert.equal(pair.manifest.targetImportVerified,false);
      const packaged=await post(base,"/api/v1/parser-pairs/package",{pair,version:"1.0.0"});
      assert.equal(packaged.status,200);
      assert.equal(packaged.headers.get("content-type"),"application/zip");
    }
  });
});
