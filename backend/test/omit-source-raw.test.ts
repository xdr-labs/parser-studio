import test from "node:test";
import assert from "node:assert/strict";
import { compilePair, validateProject, BACKEND_CAPABILITIES } from "../src/index.js";
import { sampleProject } from "./fixture.js";

function genericProject(omit?: boolean): any {
  const p: any = sampleProject();
  p.receiver.port = 6801;
  p.extraction = { format: "generic_structural", ...(omit === undefined ? {} : { omitSourceRaw: omit }) };
  p.normalization.topFields = { "generic.kv.user": { normalized_name: "username", data_type: "string" } };
  p.normalization.nsFields = {};
  p.normalization.vendorFields = {};
  p.classification.rules = [];
  return p;
}

test("default Generic Structural output keeps the full raw line and the artifact bytes are unchanged", () => {
  const ruby = compilePair(genericProject()).files[1]!.content;
  assert.match(ruby, /normalized = \{'parserstudio_source' => original\}/);
  assert.equal(ruby.includes("parserstudio_without_source_raw"), false);
});

test("omitSourceRaw: true strips only generated source_raw copies", () => {
  const p = genericProject(true);
  const validation = validateProject(p);
  assert.equal(validation.ok, true, JSON.stringify(validation));
  const ruby = compilePair(p).files[1]!.content;
  assert.match(ruby, /normalized = \{'parserstudio_source' => parserstudio_without_source_raw\(original\)\}/);
  assert.match(ruby, /def parserstudio_without_source_raw\(value\)/);
  assert.match(ruby, /generated_roots = %w\[generic watchguard_message/);
  assert.match(ruby, /out\[key\] = item.reject/);
  assert.doesNotMatch(ruby, /next if key == 'source_raw'/);
  // Mappings still read the untouched extraction.
  assert.match(ruby, /raw = parserstudio_lookup\(original, source, rule\['source_path_kind'\]\)/);
});

test("omitSourceRaw is rejected unless it is true and the format is Generic Structural", () => {
  assert.equal(validateProject(genericProject(false)).ok, false);
  const json: any = sampleProject();
  json.extraction.omitSourceRaw = true;
  assert.equal(validateProject(json).ok, false);
});

test("the option changes the artifact hash only when it is set", () => {
  const a = compilePair(genericProject()).files[1]!.sha256;
  const b = compilePair(genericProject(true)).files[1]!.sha256;
  assert.notEqual(a, b);
  assert.equal(compilePair(genericProject()).files[1]!.sha256, a);
});

test("the backend advertises the option", () => {
  assert.equal((BACKEND_CAPABILITIES.authoring as any).genericStructuralOmitSourceRaw, true);
});
