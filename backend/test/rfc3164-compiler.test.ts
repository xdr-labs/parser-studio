import test from "node:test";
import assert from "node:assert/strict";
import {sampleProject} from "./fixture.js";
import {validateProject} from "../src/validate.js";
import {compilePair} from "../src/compiler.js";
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from "../src/parser-recipe-v02.js";

function source(){
 const p=sampleProject();p.projectId="draft-rfc3164_synthetic";
 p.slug="sample_3164";p.receiver.port=6801;
 p.extraction={format:"syslog_rfc3164",syslogBodyFormat:"kv"};
 p.normalization.topFields={
  "body.src_ip":{normalized_name:"srcip",data_type:"ip"},
  "body.action":{normalized_name:"action",data_type:"string"},
  syslog_timestamp:{normalized_name:"syslog_header_time",data_type:"string"},
  syslog_time_policy:{normalized_name:"syslog_time_policy",data_type:"string"}
 };
 p.normalization.nsFields={};
 p.classification.rules=[{field:"action",operator:"equals",value:"deny",index:"threat"}];
 return p;
}
test("P0 RFC3164 strict yearless RFC3164 + quoted KV native artifact supports v0.2 stages",()=>{
 const p=source();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const files=compilePair(p);
 assert.equal(files.manifest.engineVerified,false);
 assert.deepEqual(files.files.map(x=>x.name),["customized_sample_3164.conf","customized_sample_3164"]);
 const recipe=recipeFromLegacyProject(p,"a".repeat(64),2);
 assert.equal(recipe.sourceFormat,"syslog_rfc3164");
 assert.equal(recipe.bodyFormat,"kv");
 assert.deepEqual(recipe.stages.slice(0,3).map(x=>x.op),["split_event","unwrap_syslog","parse_kv"]);
 assert.deepEqual(recipe.stages[1],{op:"unwrap_syslog",version:3164,mode:"strict_header"});
 const validated=validateRecipePair({recipe,legacyProject:p});
 assert.equal(validated.ok,true,JSON.stringify(validated));
 assert.deepEqual(compileRecipePair({recipe,legacyProject:p}).files,files.files);
});
test("P0 RFC3164 never assumes year/time zone or lower listener port and refuses timestamp coercion",()=>{
 const p=source();
 p.receiver.port=6799;
 assert.equal(validateProject(p).ok,false);
 assert.ok(validateProject(p).issues.some(i=>i.code==="syslog_port_minimum"));
 p.receiver.port=6801;
 p.normalization.topFields.syslog_timestamp={
  normalized_name:"timestamp",data_type:"date",time_format:"iso8601",timezone:"UTC"};
 assert.equal(validateProject(p).ok,false);
 assert.ok(validateProject(p).issues.some(i=>i.code==="rfc3164_unzoned_timestamp"));
});
test("P0 RFC3164 only accepts declared body parser and rejects forged RFC5424 stages",()=>{
 const p=source();
 const recipe=recipeFromLegacyProject(p,"a".repeat(64),2);
 const fake=structuredClone(recipe);
 (fake.stages[1] as any).version=1;
 assert.equal(validateRecipePair({recipe:fake,legacyProject:p}).ok,false);
 const mixed=structuredClone(p) as any;
 mixed.extraction.syslogBodyFormat="auto";
 assert.equal(validateProject(mixed).ok,false);
 const unsafe=structuredClone(p);
 unsafe.normalization.topFields["body.legacy"]={
  normalized_name:"custom.v",data_type:"date",time_format:"iso8601",timezone:"UTC"};
 assert.equal(validateProject(unsafe).ok,true);
});
