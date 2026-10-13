import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import test from "node:test";
import {
  makeLegacyUploadPlan, makeDisposablePocTestPair, requireDisposablePocWrite,
  LEGACY_POC_CAPABILITIES, type LegacyUploadPlan,
} from "../src/stellar-legacy-plan.js";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";
import type {PairExport} from "../src/types.js";

const tenant="tenant-test-123";
const digest=(s:string)=>createHash("sha256").update(s,"utf8").digest("hex");
function samplePocPair(){
  const project=sampleProject();
  project.slug="ps_api_crud_test_a1b2c3";
  project.receiver.port=7891;
  project.receiver.bindAddress="127.0.0.1";
  return makeDisposablePocTestPair(project);
}
function clone(pair:PairExport):PairExport {return structuredClone(pair);}

test("legacy pair upload plan uses exact two filenames, lengths, hashes and manifest, no raw source in status",()=>{
  const pair=compilePair(sampleProject());
  const plan=makeLegacyUploadPlan(pair,tenant,"1.0.0");
  assert.equal(plan.name,"customized_sample_firewall");
  assert.equal(plan.port,7123);
  assert.equal(plan.tenant,tenant);
  assert.deepEqual(plan.filenames.sort(),["customized_sample_firewall","customized_sample_firewall.conf"].sort());
  assert.equal(plan.proof.targetImportVerified,false);
  assert.equal(plan.proof.runtimeParsingVerified,false);
  assert.equal(JSON.stringify(plan).includes("STELLAR_INIT_BEGIN"),false);
  assert.equal(JSON.stringify(plan).includes(pair.files[0]!.content),false);
  assert.equal(LEGACY_POC_CAPABILITIES.modularUploadVerified,false);
  assert.equal(LEGACY_POC_CAPABILITIES.activationApiVerified,false);
  assert.equal(LEGACY_POC_CAPABILITIES.generalDeploymentEnabled,false);
  assert.throws(()=>requireDisposablePocWrite(plan),/POC_(?:NAME|PORT|CONF|RUBY)_UNSAFE/);
});

test("pair upload preflight rejects bad names, sizes, hashes, versions, manifest, tenant and different source ports",()=>{
  const pair=compilePair(sampleProject());
  for(const corrupt of [
    (x:PairExport)=>{x.files[0]!.bytes++;},
    (x:PairExport)=>{x.files[0]!.sha256="a".repeat(64);},
    (x:PairExport)=>{x.files[1]!.name="../escaped";},
    (x:PairExport)=>{x.manifest.fileHashes["customized_sample_firewall"]="bad";},
    (x:PairExport)=>{x.files.pop();},
    (x:PairExport)=>{x.manifest.contract="other" as any;},
    (x:PairExport)=>{x.files[0]!.content=x.files[0]!.content.replace(/port 7123/g,"port 7891");},
  ]){
    const changed=clone(pair);corrupt(changed);
    assert.throws(()=>makeLegacyUploadPlan(changed,tenant,"1.0.0"));
  }
  assert.throws(()=>makeLegacyUploadPlan(pair,"../tenant","1.0.0"),/POC_TENANT_INVALID/);
  assert.throws(()=>makeLegacyUploadPlan(pair,tenant,"bad version"),/POC_VERSION_INVALID/);
});

test("POC disposable writer accepts only reviewed template and exactly localhost/null-sink transport",()=>{
  const pair=samplePocPair();
  const plan=makeLegacyUploadPlan(pair,tenant,"1.0.0");
  const proof=requireDisposablePocWrite(plan);
  assert.equal(proof.port,7891);
  assert.equal(proof.protocols.length,2);
  assert.equal(proof.templateSha256,"032a6b92c962cc0e9ad70f9c91e545b967d299c83036170eb3ac63950001db02");
  assert.equal(proof.syntheticFixtureOnly,true);
  assert.equal(proof.runtimeParsingVerified,false);
  assert.equal(JSON.stringify(proof).includes("Base64.strict_decode64"),false);
});

test("POC write guard rejects extra filters, arbitrary self-hashed Ruby and mismatched embedded synthetic IR",()=>{
  const pair=samplePocPair();
  for(const [kind,patch] of [
    ["filter",(x:PairExport)=>{x.files[0]!.content+="\n<filter **>\n  @type record_transformer\n</filter>\n";}],
    ["sink",(x:PairExport)=>{x.files[0]!.content=x.files[0]!.content.replace("@type null","@type stdout");}],
    ["public",(x:PairExport)=>{x.files[0]!.content=x.files[0]!.content.replace("bind 127.0.0.1","bind 0.0.0.0");}],
    ["ruby",(x:PairExport)=>{x.files[1]!.content+="\n# injected Ruby";}],
  ] as const){
    const x=clone(pair);patch(x);
    for(const file of x.files){
      file.bytes=Buffer.byteLength(file.content,"utf8");file.sha256=digest(file.content);
      x.manifest.fileHashes[file.name]=file.sha256;
    }
    assert.throws(()=>requireDisposablePocWrite(makeLegacyUploadPlan(x,tenant,"1.0.0")),/POC_(CONF|RUBY)_UNSAFE|POC_RUBY_UNREVIEWED/,kind);
  }
  const nonPoc=sampleProject();
  nonPoc.slug="ps_api_crud_test_a1b2c3";
  nonPoc.receiver.port=7891;
  nonPoc.receiver.bindAddress="127.0.0.1";
  assert.throws(()=>requireDisposablePocWrite(makeLegacyUploadPlan(compilePair(nonPoc),tenant,"1.0.0")),/POC_CONF_UNSAFE/);
});
