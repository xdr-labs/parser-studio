import test from "node:test";
import assert from "node:assert/strict";
import { compilePair, validateProject } from "../src/index.js";
import { FACTORS, pairwiseReport } from "./compiler-pairwise.js";
import { compilerVariants } from "./compiler-variants.js";

const report = pairwiseReport();

// Judged by the product's own validator, not by this test: a relay wraps a
// delimited single-line event body, so it cannot front CSV, Generic Structural or
// a bare regex. Adding a factor level that makes more pairs infeasible must be a
// reviewed change to this list.
const EXPECTED_INFEASIBLE = [
  "extraction=csv & forwarder=relay",
  "extraction=generic & forwarder=relay",
  "extraction=regex & forwarder=relay",
];

test("the pairwise set covers every feasible pair of levels and reports the infeasible ones", () => {
  assert.deepEqual(report.infeasiblePairs, EXPECTED_INFEASIBLE);
  let totalPairs = 0;
  for (let a = 0; a < FACTORS.length; a++)
    for (let b = a + 1; b < FACTORS.length; b++) totalPairs += FACTORS[a]!.levels.length * FACTORS[b]!.levels.length;
  const covered = new Set<string>();
  for (const variant of report.variants)
    for (let a = 0; a < variant.levels.length; a++)
      for (let b = a + 1; b < variant.levels.length; b++) covered.add(variant.levels[a] + " & " + variant.levels[b]);
  assert.equal(covered.size, totalPairs - EXPECTED_INFEASIBLE.length);
  // Only the relay constraint rejects combinations (3 extraction levels x every other level).
  const others = FACTORS.filter(f => f.name !== "extraction" && f.name !== "forwarder").reduce((n, f) => n * f.levels.length, 1);
  assert.equal(report.combinations - report.valid, 3 * others);
});

test("every pairwise variant is a valid project and a distinct case", () => {
  const ids = new Set<string>();
  for (const variant of report.variants) {
    assert.ok(!ids.has(variant.id), "duplicate " + variant.id);
    ids.add(variant.id);
    const result = validateProject(variant.project);
    assert.equal(result.ok, true, variant.id + ": " + JSON.stringify(result.ok ? [] : result.issues));
  }
  assert.ok(report.variants.length >= 40, "unexpectedly small pairwise set: " + report.variants.length);
});

test("combinations a single-axis list cannot reach are in the matrix: CSV and mixed CSV together with event profiles", () => {
  const has = (format: string, profiles: boolean) => report.variants.some(v =>
    v.project.extraction.format === format && Boolean(v.project.normalization.eventProfiles) === profiles
    && (format !== "mixed" || (v.project.extraction.mixedFormats ?? []).includes("csv")));
  assert.ok(has("csv", true), "no csv + eventProfiles variant");
  assert.ok(has("mixed", true), "no mixed(csv) + eventProfiles variant");
  assert.ok(has("csv", false) && has("mixed", false));
});

test("each pairwise variant compiles, and compilerVariants() hands them to every consumer", () => {
  const all = compilerVariants();
  const pairwise = all.filter(v => v.axis === "pairwise");
  assert.equal(pairwise.length, report.variants.length);
  for (const variant of pairwise) assert.ok(compilePair(variant.project).files.length >= 2, variant.id);
});
