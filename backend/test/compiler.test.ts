import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { compilePair, validateProject } from "../src/index.js";
import { sampleProject } from "./fixture.js";
test("R1.5 valid synthetic project model", () => { assert.equal(validateProject(sampleProject()).ok,true); });
test("strict invalid slugs, ports, injection, unknown operators", () => {
  const changes = [
    (p:any)=>{p.slug="../etc/passwd";}, (p:any)=>{p.slug="FOO";},
    (p:any)=>{p.receiver.port=0;},(p:any)=>{p.receiver.port=65536;},
    (p:any)=>{p.receiver.protocols=["udp","udp"];},(p:any)=>{p.receiver.protocols=["http"];},
    (p:any)=>{p.receiver.extra="@include /etc/passwd";},(p:any)=>{p.extraction.format="ruby";},
    (p:any)=>{p.receiver.tcpFraming="delimiter";},
    (p:any)=>{p.normalization.topFields.action.data_type="obejct";},
    (p:any)=>{p.unsupportedOpaqueBlocks=[{sourceRef:"opaque"}];}
  ];
  for (const change of changes) {const p:any=sampleProject();change(p);assert.equal(validateProject(p).ok,false,JSON.stringify(p));}
});
test("reject mappings to reserved/duplicate names and unknown classification fields", () => {
  const p=sampleProject();
  p.normalization.nsFields.invalid={normalized_name:"srcip",data_type:"string"};
  assert.ok(validateProject(p).issues.some(x=>x.code==="destination_collision"));
  delete p.normalization.nsFields.invalid;
  p.normalization.topFields["new_source"]={normalized_name:"stellar_log_index",data_type:"string"};
  assert.ok(validateProject(p).issues.some(x=>x.code==="reserved_field"));
  delete p.normalization.topFields["new_source"];
  p.classification.rules[0]!.field="not_extracted";
  assert.ok(validateProject(p).issues.some(x=>x.code==="unmapped_classification_field"));
});
test("files share identity, expected conf sections, and deterministic SHA-256", () => {
 const p=sampleProject();const result=compilePair(p);
 assert.deepEqual(result.files.map(x=>x.name),["customized_sample_firewall.conf","customized_sample_firewall"]);
 assert.equal(result.contract,"host-customized-pair.v0.1");assert.equal(result.manifest.status,"DRAFT");
 assert.equal(result.manifest.engineVerified,false);assert.equal(result.manifest.targetImportVerified,false);
 for(const f of result.files)assert.equal(f.sha256,createHash("sha256").update(f.content).digest("hex"));
 assert.deepEqual(compilePair(p),result);
 const conf=result.files[0]!.content;
 assert.equal((conf.match(/<source>/g)||[]).length,2);
 assert.match(conf,/@type udp/);assert.match(conf,/@type tcp/);
 assert.match(conf,/@type customized_sample_firewall/);
 assert.match(conf,/tag customized_sample_firewall/);
 assert.match(conf,/<match customized_sample_firewall\.\*\*>/);
 assert.match(conf,/key stellar_log_index/);
 assert.match(conf,/pattern \/\^session\$\//);assert.match(conf,/pattern \/\^threat\$\//);
});
test("fragment includes only one set of markers, safe literal payload, and Ruby callback", () => {
 const p=sampleProject();p.vendor="Pretend #{Kernel.exit} 'vendor'";
 const ruby=compilePair(p).files[1]!.content;
 for(const marker of ["STELLAR_INIT_BEGIN","STELLAR_INIT_END","STELLAR_PARSE_BEGIN","STELLAR_PARSE_END"])
   assert.equal(ruby.split(marker).length-1,1);
 assert.match(ruby,/def parse\(text\)/);assert.match(ruby,/yield event_time, normalized/);
 const payload=ruby.match(/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/)?.[1];
 assert.ok(payload);
 assert.equal(JSON.parse(Buffer.from(payload!,"base64").toString("utf8")).vendor,p.vendor);
 assert.equal(ruby.includes("Kernel.exit"),false);
});
test("compiler refuses invalid project; canonical map key order doesn't change artifacts", () => {
 const invalid=sampleProject();invalid.slug="x\n@include /etc";assert.throws(()=>compilePair(invalid),/Invalid parser project/);
 const a=sampleProject(),b=sampleProject();
 b.normalization.topFields=Object.fromEntries(Object.entries(b.normalization.topFields).reverse());
 assert.deepEqual(compilePair(a),compilePair(b));
});
