/**
 * Offline synthetic-only gate: generated two-file fixtures must import exactly,
 * recompile without byte changes, and refuse editability after modification.
 * Never read customer fixtures, run Ruby, or connect to a Fluentd listener.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { compilePair, inspectPair } from "../src/index.js";

const dir = resolve(process.env["PAIR_OUTPUT_DIR"] || ".tmp/native-fixtures");
const confNames = readdirSync(dir).filter(name => /^customized_[a-z][a-z0-9_]*\.conf$/.test(name)).sort();
assert.equal(confNames.length, 8, "Expected exactly eight generated, synthetic parser profiles");

const hash = (source: string): string => createHash("sha256").update(source, "utf8").digest("hex");
const originals: Record<string, string> = {};
for (const confName of confNames) {
  const name = confName.slice(0, -5);
  const confContent = readFileSync(resolve(dir, confName), "utf8");
  const fragmentContent = readFileSync(resolve(dir, name), "utf8");
  const imported = inspectPair({ name, confContent, fragmentContent });

  assert.equal(imported.importStatus, "EDITABLE_EXACT", name + ": generated pair not editable");
  assert.equal(imported.roundTripVerified, true);
  assert.equal(imported.diagnostics.length, 0, name + ": generated pair unexpectedly warned");
  assert.ok(imported.portableProject, name + ": no portable model");
  assert.equal(imported.originalHashes.conf, hash(confContent));
  assert.equal(imported.originalHashes.fragment, hash(fragmentContent));
  originals[confName] = imported.originalHashes.conf;
  originals[name] = imported.originalHashes.fragment;

  const rebuilt = compilePair(imported.portableProject);
  assert.equal(rebuilt.files[0]?.name, confName);
  assert.equal(rebuilt.files[1]?.name, name);
  assert.equal(rebuilt.files[0]?.content, confContent, name + ": regenerated CONF differs");
  assert.equal(rebuilt.files[1]?.content, fragmentContent, name + ": regenerated Ruby differs");

  const privateSentinel = "SYNTHETIC_PRIVATE_IMPORT_SENTINEL_NOT_FOR_OUTPUT";
  const changed = inspectPair({ name, confContent: confContent + "\n# " + privateSentinel, fragmentContent });
  assert.equal(changed.importStatus, "OPAQUE_READ_ONLY", name + ": changed pair became editable");
  assert.equal(changed.roundTripVerified, false);
  assert.equal(changed.portableProject, null);
  assert.ok(changed.diagnostics.some(x => x.code === "PAIR_NOT_REPRODUCIBLE"));
  assert.equal(JSON.stringify(changed).includes(privateSentinel), false, "Input content was echoed");
}

const backendHead = execFileSync("git", ["rev-parse", "HEAD"], { encoding:"utf8" }).trim();
const report = {
  kind: "xdr-labs.parser-studio.synthetic-pair-import.v0.1",
  backendHead,
  origin: "synthetic-repository-fixtures",
  verifiedExactPairs: confNames.length,
  rejectedModifiedPairs: confNames.length,
  targetImportVerified: false,
  originalHashes: originals,
};
writeFileSync(".tmp/synthetic-import-report.json", JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
console.log("Synthetic pair Import + recompile: " + confNames.length +
  " exact pairs and " + confNames.length + " opaque tamper cases PASS; no target upload.");
