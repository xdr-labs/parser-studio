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
for (const project of [json,kv]) {
  const pair = compilePair(project);
  for (const file of pair.files) {
    writeFileSync(resolve(out, file.name), file.content, {flag:"w",mode:0o600});
    process.stdout.write(file.name + " " + file.sha256 + "\n");
  }
}
