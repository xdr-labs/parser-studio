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
test("generated CSV parser strips field-edge whitespace without enabling liberal parsing",()=>{
 const ruby=compilePair(sampleProject()).files[1]!.content;
 assert.match(ruby,/CSV\.parse_line\(text, col_sep: separator, liberal_parsing: false, strip: true\)/);
 assert.equal(ruby.includes("liberal_parsing: true"),false);
});

test("compiler refuses invalid project; canonical map key order doesn't change artifacts", () => {
 const invalid=sampleProject();invalid.slug="x\n@include /etc";assert.throws(()=>compilePair(invalid),/Invalid parser project/);
 const a=sampleProject(),b=sampleProject();
 b.normalization.topFields=Object.fromEntries(Object.entries(b.normalization.topFields).reverse());
 assert.deepEqual(compilePair(a),compilePair(b));
});


test("bounded Syslog Regex body validates only with safe named captures and compiles deterministically",()=>{
 const p=sampleProject();p.receiver.port=7123;
 p.extraction={format:"syslog_rfc3164",syslogBodyFormat:"regex",
  pattern:"^%FTD-\\d-\\d+: Built \\w+ \\w+ connection (?<connection_id>\\d+) for [^:]+:(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<src_port>\\d+) to [^:]+:(?<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<dst_port>\\d+)$"};
 p.normalization.topFields={
  "body.src_ip":{normalized_name:"srcip",data_type:"ip"},
  "body.src_port":{normalized_name:"srcport",data_type:"port"},
  "body.dst_ip":{normalized_name:"dstip",data_type:"ip"},
  "body.dst_port":{normalized_name:"dstport",data_type:"port"},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[];
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const a=compilePair(p),b=compilePair(structuredClone(p));
 assert.deepEqual(a,b);
 const unsafe=structuredClone(p);
 unsafe.extraction.pattern="(?<x>.*)+";
 assert.equal(validateProject(unsafe).ok,false);
 assert.ok(validateProject(unsafe).issues.some(x=>x.code.startsWith("regex_")));
});


test("Generic Structural compiler is opt-in, bounded and keeps legacy artifact bytes isolated",()=>{
 const legacy=compilePair(sampleProject()).files[1]!.content;
 assert.equal(legacy.includes("parserstudio_generic_structural"),false);
 assert.equal(legacy.includes("parserstudio_source"),false);
 const p=sampleProject();
 p.receiver.port=7501;
 p.extraction={format:"generic_structural"};
 p.normalization.topFields={
  "syslog.pri":{normalized_name:"source_pri",data_type:"string"},
  "generic.kv.AD-Domain":{normalized_name:"ad_domain",data_type:"string"},
  "body.event.id":{normalized_name:"event_id",data_type:"integer"},
  "asa.src_ip":{normalized_name:"srcip",data_type:"ip"},
  "asa.dst_port":{normalized_name:"dstport",data_type:"port"},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};p.classification.rules=[];
 const validation=validateProject(p);
 assert.equal(validation.ok,true,JSON.stringify(validation));
 const pair=compilePair(p);
 const ruby=pair.files[1]!.content;
 assert.match(ruby,/when 'generic_structural'/);
 assert.match(ruby,/def parserstudio_generic_structural\(text\)/);
 assert.match(ruby,/def parserstudio_generic_short_rfc5424_structured\(text\)/);
 assert.match(ruby,/def parserstudio_generic_prefixed_json\(text\)/);
 assert.match(ruby,/def parserstudio_generic_junos_rfc5424_sd\(text\)/);
 assert.match(ruby,/def parserstudio_generic_space_kv\(text\)/);
 assert.match(ruby,/pieces\.each_with_index/);
 assert.match(ruby,/def parserstudio_generic_watchguard\(text\)/);
 assert.match(ruby,/def parserstudio_generic_juniper_legacy\(text\)/);
 assert.match(ruby,/def parserstudio_generic_delimited_comma_kv\(text\)/);
 assert.match(ruby,/def parserstudio_generic_bracket_colon_kv\(text\)/);
 assert.match(ruby,/def parserstudio_generic_rfc3164_delimited_comma_kv\(text\)/);
 assert.match(ruby,/normalized = \{'parserstudio_source' => original\}/);
 assert.match(ruby,/GENERIC STRUCTURAL|Generic Structural|generic structural/i);
 const low=structuredClone(p);low.receiver.port=6799;
 assert.equal(validateProject(low).ok,false);
 assert.ok(validateProject(low).issues.some(x=>x.code==="syslog_port_minimum"));
});
