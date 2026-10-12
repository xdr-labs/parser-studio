import test from "node:test";
import assert from "node:assert/strict";
import {listParserTemplates,instantiateParserTemplate} from "../src/parser-templates.js";
import {validateProject} from "../src/validate.js";
import {compilePair} from "../src/compiler.js";
import {buildArtifactPackage} from "../src/artifact-package.js";

const config={projectId:"fixture_synthetic",slug:"fixture_parser",port:7123,
  protocols:["udp" as const],revision:1};
test("six offline templates are discoverable and explicitly unverified",()=>{
  const templates=listParserTemplates();
  assert.deepEqual(templates.map(x=>x.format),[
    "json","kv","csv","syslog_rfc5424","cef","leef",
  ]);
  assert.equal(new Set(templates.map(x=>x.id)).size,6);
  assert.equal(templates.every(x=>x.targetVerified===false&&
    x.requiresNativeVerification===true),true);
  assert.equal(JSON.stringify(templates).includes("SECRET"),false);
});
test("each starter compiles a bounded, deterministic DRAFT Ruby + CONF artifact",()=>{
  for(const template of listParserTemplates()){
    const project=instantiateParserTemplate(template.id,{
      ...config,port:template.format==="syslog_rfc5424"?6800:7123,
    });
    assert.equal(project.schemaRevision,"0.1");
    assert.equal(project.extraction.format,template.format);
    assert.equal(validateProject(project).ok,true,template.id);
    const pair=compilePair(project);
    assert.equal(pair.files.length,2);
    const artifact=buildArtifactPackage(pair,"1.0.0");
    assert.equal(artifact.manifest.targetImportVerified,false);
    assert.equal(artifact.manifest.selectedParserPort,project.receiver.port);
    assert.deepEqual(buildArtifactPackage(compilePair(project),"1.0.0").zip,artifact.zip);
  }
});
test("template clone uses same user-selected CONF and sensor port, Syslog min 6800",()=>{
  assert.throws(()=>instantiateParserTemplate("rfc5424",{
    ...config,port:6799,
  }),/TEMPLATE_PROJECT_INVALID/);
  const accepted=instantiateParserTemplate("rfc5424",{...config,port:6800});
  assert.equal(accepted.receiver.port,6800);
  assert.equal(accepted.extraction.format,"syslog_rfc5424");
  assert.match(compilePair(accepted).files[0]!.content,/\bport 6800\b/);
});
test("different user project/slug creates distinct Ruby/CONF revision without mutating catalog",()=>{
  const a=instantiateParserTemplate("json",config);
  const b=instantiateParserTemplate("json",{
    ...config,projectId:"fixture_second",slug:"fixture_second",port:7342,
  });
  const first=buildArtifactPackage(compilePair(a),"1.0.0");
  const second=buildArtifactPackage(compilePair(b),"1.0.0");
  assert.notEqual(first.manifest.artifactRevisionId,second.manifest.artifactRevisionId);
  a.normalization.msgOriginSource="MUTATED_LOCAL";
  assert.notEqual(instantiateParserTemplate("json",config).normalization.msgOriginSource,
    "MUTATED_LOCAL");
});
test("unknown ID, unsafe project slugs, protocols or credential fields are rejected",()=>{
  assert.throws(()=>instantiateParserTemplate("nonexistent",config),/TEMPLATE_NOT_FOUND/);
  assert.throws(()=>instantiateParserTemplate("json",{...config,slug:"../../bad"}),
    /TEMPLATE_PROJECT_INVALID/);
  assert.throws(()=>instantiateParserTemplate("json",{...config,protocols:["http"] as any}),
    /TEMPLATE_PROJECT_INVALID/);
  assert.throws(()=>instantiateParserTemplate("json",{...config,apiKey:"secret"} as any),
    /TEMPLATE_OPTIONS_INVALID/);
});
