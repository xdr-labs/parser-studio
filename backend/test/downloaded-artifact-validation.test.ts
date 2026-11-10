import test from "node:test";
import assert from "node:assert/strict";
import { compilePair } from "../src/index.js";
import { buildArtifactPackage } from "../src/artifact-package.js";
import { expandZipDownload, validateDownloads, type DownloadedFile } from "../src/downloaded-artifact-validation.js";
import { sampleProject } from "./fixture.js";

function realPair() {
  const project = sampleProject();
  const pair = compilePair(project);
  const conf = pair.files.find(f => f.name.endsWith(".conf"))!;
  const ruby = pair.files.find(f => !f.name.endsWith(".conf"))!;
  const file = (id: string, name: string, content: string, over: Partial<DownloadedFile> = {}): DownloadedFile =>
    ({ id, testKey: "w0-t1", name, content, synthetic: null, ...over });
  return { conf, ruby, file };
}

test("a real compiled Ruby Fragment and .conf downloaded in one test pass as a validated pair", () => {
  const { conf, ruby, file } = realPair();
  const report = validateDownloads([file("a", ruby.name, ruby.content), file("b", conf.name, conf.content)]);
  assert.deepEqual(report.failures, []);
  assert.equal(report.real.fragments, 1);
  assert.equal(report.real.confs, 1);
  assert.equal(report.real.pairs, 1);
  assert.equal(report.uniqueRealFragments, 1);
});

test("code after STELLAR_PARSE_END in a downloaded fragment fails the gate", () => {
  const { conf, ruby, file } = realPair();
  const report = validateDownloads([file("a", ruby.name, ruby.content + "\ndef late\nend\n"), file("b", conf.name, conf.content)]);
  assert.equal(report.failures.length, 1);
  assert.ok(report.failures[0]!.rules.includes("FRAG-NO-CODE-AFTER-PARSE-END"));
  assert.equal(report.failures[0]!.id, "a");
});

test("a downloaded .conf that violates the contract fails even when it has no matching fragment", () => {
  const { conf } = realPair();
  const report = validateDownloads([{ id: "c", testKey: "w0-t2", name: conf.name, content: conf.content.replace("capitalize_regex_backreference yes", ""), synthetic: null }]);
  assert.ok(report.failures[0]!.rules.includes("CONF-CAPITALIZE"));
  assert.equal(report.real.pairs, 0);
});

test("artifact-shaped content that is not declared synthetic is validated, never skipped (fail closed)", () => {
  const report = validateDownloads([
    { id: "m", testKey: "w0-t3", name: "customized_demo_firewall", content: "# synthetic test Ruby fragment\n", synthetic: null },
    { id: "n", testKey: "w0-t3", name: "customized_demo_firewall.conf", content: "# synthetic test CONF for port 6801\n", synthetic: null },
  ]);
  assert.equal(report.failures.length, 2);
  assert.ok(report.failures.some(f => f.rules.includes("FRAG-MARKERS")));
  assert.ok(report.failures.some(f => f.rules.includes("CONF-SOURCE-TYPES")));
});

test("declared synthetic downloads are counted and explained but not treated as validated output", () => {
  const report = validateDownloads([
    { id: "s", testKey: "w0-t4", name: "customized_demo_firewall", content: "# synthetic\n", synthetic: "Route-mocked compile response used to test the download button." },
  ]);
  assert.deepEqual(report.failures, []);
  assert.equal(report.real.fragments, 0);
  assert.equal(report.synthetic.count, 1);
  assert.deepEqual(report.synthetic.reasons, ["Route-mocked compile response used to test the download button."]);
});

test("other downloads (sender scripts, JSON) are listed as unvalidated, not silently dropped", () => {
  const report = validateDownloads([{ id: "p", testKey: "w0-t5", name: "parser_studio_test_sender.py", content: "print(1)\n", synthetic: null }]);
  assert.equal(report.real.other, 1);
  assert.deepEqual(report.otherNames, ["parser_studio_test_sender.py"]);
  assert.deepEqual(report.failures, []);
});

test("two same-named fragments in one test are validated individually and reported as ambiguous", () => {
  const { conf, ruby, file } = realPair();
  const report = validateDownloads([
    file("a1", ruby.name, ruby.content), file("a2", ruby.name, ruby.content + "\ndef late\nend\n"), file("b", conf.name, conf.content),
  ]);
  assert.equal(report.real.ambiguousPairs, 1);
  assert.equal(report.real.pairs, 0);
  assert.deepEqual(report.failures.map(f => f.id), ["a2"]);
});

test("identical downloads are validated once per content but still counted", () => {
  const { ruby, file } = realPair();
  const report = validateDownloads([file("a", ruby.name, ruby.content), file("b", ruby.name, ruby.content, { testKey: "w1-t9" })]);
  assert.equal(report.real.fragments, 2);
  assert.equal(report.uniqueRealFragments, 1);
});

// ---- ZIP downloads: the package a user receives holds the pair plus manifest.json ----

function realPackage() {
  const pair = compilePair(sampleProject());
  return { pair, pkg: buildArtifactPackage(pair, "1.0.0") };
}

test("a real artifact ZIP expands to the pair and manifest with matching hashes and no problems", () => {
  const { pair, pkg } = realPackage();
  const expanded = expandZipDownload(pkg.zip);
  assert.deepEqual(expanded.problems, []);
  assert.deepEqual(expanded.entries.map(e => e.name).sort(), [...pair.files.map(f => f.name), "manifest.json"].sort());
  const ruby = pair.files.find(f => !f.name.endsWith(".conf"))!;
  assert.equal(expanded.entries.find(e => e.name === ruby.name)!.content, ruby.content);
});

test("a flipped byte inside a stored ZIP entry is reported as a CRC problem", () => {
  const { pkg } = realPackage();
  const tampered = Buffer.from(pkg.zip);
  const at = tampered.indexOf(Buffer.from("STELLAR_INIT_BEGIN"));
  assert.ok(at > 0);
  tampered[at] = tampered[at]! ^ 0x01;
  const expanded = expandZipDownload(tampered);
  assert.ok(expanded.problems.some(p => p.startsWith("ZIP_CRC_MISMATCH")), JSON.stringify(expanded.problems));
});

test("a manifest whose recorded hash differs from the entry is reported", () => {
  const { pair, pkg } = realPackage();
  const hash = Object.values(pkg.manifest.fileHashes)[0] as string;
  const tampered = Buffer.from(pkg.zip);
  tampered.write(hash.slice(0, -1) + (hash.endsWith("0") ? "1" : "0"), tampered.indexOf(Buffer.from(hash)));
  const expanded = expandZipDownload(tampered);
  assert.ok(expanded.problems.some(p => p.startsWith("ZIP_MANIFEST_HASH_MISMATCH")), JSON.stringify(expanded.problems));
  assert.ok(pair.files.length === 2);
});

test("non-ZIP bytes and unsafe entry names are rejected, never expanded", () => {
  assert.ok(expandZipDownload(Buffer.from("not a zip")).problems.includes("ZIP_INVALID"));
  const { pkg } = realPackage();
  const renamed = Buffer.from(pkg.zip);
  const name = Buffer.from("manifest.json");
  for (let at = renamed.indexOf(name); at >= 0; at = renamed.indexOf(name, at + 1)) renamed.write("../ifest.json", at);
  const expanded = expandZipDownload(renamed);
  assert.ok(expanded.problems.some(p => p.startsWith("ZIP_UNSAFE_ENTRY_NAME")), JSON.stringify(expanded.problems));
  assert.ok(!expanded.entries.some(e => e.name.includes("..")));
});
