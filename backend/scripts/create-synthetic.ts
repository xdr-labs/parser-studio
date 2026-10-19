import { compilePair } from "../src/index.js";
import { safeSyntheticOutputDirectory, writeSyntheticFixture } from "../src/synthetic-fixture-safety.js";
import { sampleProject } from "../test/fixture.js";

const out = safeSyntheticOutputDirectory(process.env["PAIR_OUTPUT_DIR"]);
const json = sampleProject();
const kv = sampleProject();
kv.slug = "sample_kv";
kv.extraction = {format:"kv"};
kv.normalization.topFields = {
  "src_ip": {normalized_name:"srcip", data_type:"ip"},
  "dst_port": {normalized_name:"dstport",data_type:"port"},
  action: {normalized_name:"action",data_type:"string"},
};
kv.normalization.nsFields = {};
const extended = sampleProject();
extended.slug = "sample_extended";
extended.normalization.topFields["event_time"] = {
  normalized_name: "timestamp", data_type: "date", time_format: "iso8601", timezone: "UTC",
};
extended.normalization.vendorFields["username"] = { normalized_name: "username", data_type: "string" };
const csv = sampleProject();
csv.slug = "sample_csv";
csv.extraction = { format: "csv", csvColumns: ["src_ip", "dst_port", "action"], csvDelimiter: "," };
csv.normalization.topFields = {
  src_ip: { normalized_name: "srcip", data_type: "ip" },
  dst_port: { normalized_name: "dstport", data_type: "port" },
  action: { normalized_name: "action", data_type: "string" },
};
csv.normalization.nsFields = {};

const syslog = sampleProject();
syslog.slug = "sample_syslog";
syslog.extraction = { format: "syslog_rfc5424", syslogBodyFormat: "kv" };
syslog.normalization.topFields = {
  "body.src_ip": { normalized_name: "srcip", data_type: "ip" },
  "body.action": { normalized_name: "action", data_type: "string" },
  syslog_timestamp: { normalized_name: "timestamp", data_type: "date", time_format: "iso8601", timezone: "UTC" },
};
syslog.normalization.nsFields = {};

// Explicit RFC5424 envelopes containing bounded, standalone CEF/LEEF bodies.
const syslogCef = sampleProject();
syslogCef.slug = "sample_syslog_cef";
syslogCef.extraction = {format:"syslog_rfc5424", syslogBodyFormat:"cef"};
syslogCef.normalization.topFields = {
  "body.src": {normalized_name:"srcip",data_type:"ip"},
  "body.dpt": {normalized_name:"dstport",data_type:"port"},
  "body.act": {normalized_name:"action",data_type:"string"},
  "syslog_timestamp": {normalized_name:"timestamp",data_type:"date",time_format:"iso8601",timezone:"UTC"},
};
syslogCef.normalization.nsFields = {};
const syslogLeef = sampleProject();
syslogLeef.slug = "sample_syslog_leef";
syslogLeef.extraction = {format:"syslog_rfc5424", syslogBodyFormat:"leef"};
syslogLeef.normalization.topFields = {
  "body.src": {normalized_name:"srcip",data_type:"ip"},
  "body.dstPort": {normalized_name:"dstport",data_type:"port"},
  "body.act": {normalized_name:"action",data_type:"string"},
  "syslog_timestamp": {normalized_name:"timestamp",data_type:"date",time_format:"iso8601",timezone:"UTC"},
};
syslogLeef.normalization.nsFields = {};

const cef = sampleProject();
cef.slug = "sample_cef";
cef.extraction = { format: "cef" };
cef.normalization.topFields = {
  src: { normalized_name: "srcip", data_type: "ip" },
  dst: { normalized_name: "dstip", data_type: "ip" },
  dpt: { normalized_name: "dstport", data_type: "port" },
  act: { normalized_name: "action", data_type: "string" },
};
cef.normalization.nsFields = {};

const leef = sampleProject();
leef.slug = "sample_leef";
leef.extraction = { format: "leef" };
leef.normalization.topFields = {
  src: { normalized_name: "srcip", data_type: "ip" },
  dstPort: { normalized_name: "dstport", data_type: "port" },
  act: { normalized_name: "action", data_type: "string" },
};
leef.normalization.nsFields = {};

const enriched = sampleProject();
enriched.slug = "sample_enriched";
enriched.normalization.topFields.endpoint = { normalized_name: "endpoint", data_type: "string" };
enriched.enrichment = [
  { operator: "set_const", target: "log.source_label", value: "synthetic" },
  { operator: "lowercase", source: "action", target: "log.action_lower" },
  { operator: "copy", source: "srcip", target: "log.original_srcip" },
  { operator: "uppercase", source: "log.action_lower", target: "log.action_upper" },
  { operator: "split_field", source: "endpoint", delimiter: ":", targets: ["log.endpoint_host", "log.endpoint_port"] },
  { operator: "merge_fields", sources: ["log.endpoint_host", "log.endpoint_port"], delimiter: ":", target: "log.endpoint_joined" },
];
enriched.classification.rules[0]!.field = "log.action_lower";
for (const project of [json,kv,extended,csv,syslog,syslogCef,syslogLeef,cef,leef,enriched]) {
  const pair = compilePair(project);
  for (const file of pair.files) {
    writeSyntheticFixture(out, file.name, file.content);
    process.stdout.write(file.name + " " + file.sha256 + "\n");
  }
}
