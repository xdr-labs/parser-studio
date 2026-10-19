import assert from "node:assert/strict";
import test from "node:test";
import { compilePair, validateProject } from "../src/index.js";
import { sampleProject } from "./fixture.js";

test("CSV, RFC5424 Syslog, CEF and LEEF are explicitly modelled as separate operators", () => {
  for (const format of ["csv", "syslog_rfc5424", "cef", "leef"] as const) {
    const model = sampleProject();
    model.extraction = format === "csv"
      ? { format, csvColumns: ["src_ip", "dst_port", "action"], csvDelimiter: "," }
      : format === "syslog_rfc5424"
        ? { format, syslogBodyFormat: "kv" }
        : { format };
    const result = validateProject(model);
    assert.deepEqual(result.issues, [], format + JSON.stringify(result.issues));
    const pair = compilePair(model);
    assert.equal(pair.files.length, 2);
    assert.equal(pair.manifest.engineVerified, false);
  }
});

test("malformed CSV options and syntax-changing untrusted extraction settings are rejected", () => {
  const reject = [
    { format: "csv" }, // must name its columns
    { format: "csv", csvColumns: ["src_ip", "src_ip"] },
    { format: "csv", csvColumns: ["__proto__"] },
    { format: "csv", csvColumns: ["src_ip", "dst_port"], csvDelimiter: "\n" },
    { format: "json", csvColumns: ["a"] },
    { format: "kv", syslogBodyFormat: "json" },
    { format: "syslog_rfc5424", syslogBodyFormat: "python" },
    { format: "cef", rubyCode: "Kernel.exit" },
  ];
  for (const extraction of reject) {
    const project = sampleProject();
    project.extraction = extraction as any;
    const check = validateProject(project);
    assert.equal(check.ok, false, JSON.stringify(extraction));
    assert.throws(() => compilePair(project), /Invalid parser project/);
  }
});

test("CSV output columns require strict field naming and 1..100 entries", () => {
  const project = sampleProject();
  project.extraction = { format: "csv", csvColumns: ["hostname", "action"], csvDelimiter: ";" };
  assert.equal(validateProject(project).ok, true);
  for (const column of ["a.b", "two spaces", "bad\ncolumn", "constructor"]) {
    project.extraction.csvColumns = ["hostname", column];
    assert.equal(validateProject(project).ok, false, column);
  }
});

test("format metadata influences artifact deterministically, not parser naming", () => {
  const a = sampleProject(), b = sampleProject();
  a.extraction = { format: "syslog_rfc5424", syslogBodyFormat: "json" };
  b.extraction = { format: "syslog_rfc5424", syslogBodyFormat: "kv" };
  const x = compilePair(a), y = compilePair(b);
  assert.deepEqual(x.files.map(file => file.name), y.files.map(file => file.name));
  assert.notEqual(x.files[1]?.sha256, y.files[1]?.sha256);
});

test("RFC5424 nested standalone CEF and LEEF body formats are explicit supported profiles", () => {
  for (const body of ["cef", "leef"] as const) {
    const project=sampleProject();
    project.extraction={format:"syslog_rfc5424",syslogBodyFormat:body};
    project.normalization.topFields = body==="cef"
      ? {"body.src":{normalized_name:"srcip",data_type:"ip"},
         "body.dpt":{normalized_name:"dstport",data_type:"port"},
         "body.act":{normalized_name:"action",data_type:"string"}}
      : {"body.src":{normalized_name:"srcip",data_type:"ip"},
         "body.dstPort":{normalized_name:"dstport",data_type:"port"},
         "body.act":{normalized_name:"action",data_type:"string"}};
    project.normalization.nsFields={};
    assert.equal(validateProject(project).ok,true,body);
    const pair=compilePair(project);
    assert.equal(pair.files.length,2);
    assert.equal(pair.manifest.targetImportVerified,false);
  }
});
