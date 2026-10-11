import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { compilePair } from "../src/index.js";
import { sampleProject } from "../test/fixture.js";

const out = resolve(process.env["PAIR_OUTPUT_DIR"] || ".tmp/native-fixtures");
mkdirSync(out, {recursive: true});
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
for (const project of [json,kv,extended]) {
  const pair = compilePair(project);
  for (const file of pair.files) {
    writeFileSync(resolve(out, file.name), file.content, {flag:"w",mode:0o600});
    process.stdout.write(file.name + " " + file.sha256 + "\n");
  }
}
