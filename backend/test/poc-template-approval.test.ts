import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {
  REVIEWED_POC_TEMPLATE_SHA256S, makeDisposablePocTestPair, makeLegacyUploadPlan,
  pocTemplateSha256, requireDisposablePocWrite,
} from "../src/stellar-legacy-plan.js";
import {sampleProject} from "./fixture.js";
import type {PairExport} from "../src/types.js";
import {createHash} from "node:crypto";

// Regression gate for the reviewed-template check (POC_RUBY_UNREVIEWED) of the disposable
// POC upload path. These tests are part of the required product gate (test:authoring).
// They never add an approval: the accept path injects its own allowlist, and the real list
// is only checked for consistency with the template the current compiler produces.

const tenant = "tenant-test-123";
// Owner approval of 2026-11-13 for the audited Ruby 2.4.9 template in PR #307.
// Earlier owner-reviewed templates remain in KNOWN_TEMPLATES for existing evidence.
const APPROVED_CURRENT_TEMPLATE_SHA256 = "95d2bdc6466d1d82f728aec7c0fc2ac222f1afd49a9bcbdf10f17f1ee6c88a2c";
const digest = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

function pocPair(): PairExport {
  const project = sampleProject();
  project.slug = "ps_api_crud_test_a1b2c3";
  project.receiver.port = 7891;
  project.receiver.bindAddress = "127.0.0.1";
  return makeDisposablePocTestPair(project);
}
const rubyOf = (pair: PairExport) => pair.files[1]!.content;
const guard = (pair: PairExport, approved?: ReadonlySet<string>) =>
  requireDisposablePocWrite(makeLegacyUploadPlan(pair, tenant, "1.0.0"), approved);

function tampered(pair: PairExport, patch: (x: PairExport) => void): PairExport {
  const x = structuredClone(pair);
  patch(x);
  for (const file of x.files) {
    file.bytes = Buffer.byteLength(file.content, "utf8");
    file.sha256 = digest(file.content);
    x.manifest.fileHashes[file.name] = file.sha256;
  }
  return x;
}

test("the real reviewed list accepts exactly the owner-approved current template and rejects any altered one", () => {
  const pair = pocPair();
  const sha = pocTemplateSha256(rubyOf(pair)).templateSha;
  // The hash depends on the zlib build of the Node runtime (the deflated Unicode table is part of
  // the hashed text); CI pins Node 22. This line makes a drift visible in the CI log.
  console.log("POC_TEMPLATE_STATUS node=" + process.version + " sha256=" + sha + " listed=" + REVIEWED_POC_TEMPLATE_SHA256S.has(sha));
  assert.equal(sha, APPROVED_CURRENT_TEMPLATE_SHA256, "the generated POC template changed: it needs a new owner review");
  assert.ok(REVIEWED_POC_TEMPLATE_SHA256S.has(sha));
  assert.equal(guard(pair).templateSha256, sha);
  assert.throws(() => guard(tampered(pair, x => { x.files[1]!.content += "\n# injected Ruby"; })), /POC_RUBY_UNREVIEWED/);
});

test("an approved template is accepted and the proof carries its hash", () => {
  const pair = pocPair();
  const sha = pocTemplateSha256(rubyOf(pair)).templateSha;
  const proof = guard(pair, new Set([sha]));
  assert.equal(proof.templateSha256, sha);
  assert.equal(proof.port, 7891);
  assert.equal(proof.syntheticFixtureOnly, true);
  assert.equal(proof.runtimeParsingVerified, false);
});

test("an unreviewed template is rejected with POC_RUBY_UNREVIEWED", () => {
  const pair = pocPair();
  assert.throws(() => guard(pair, new Set()), /POC_RUBY_UNREVIEWED/);
  assert.throws(() => guard(pair, new Set(["0".repeat(64)])), /POC_RUBY_UNREVIEWED/);
});

test("even with the template hash approved, any change to the Ruby or the transport is rejected", () => {
  const pair = pocPair();
  const approved: ReadonlySet<string> = new Set([pocTemplateSha256(rubyOf(pair)).templateSha]);
  assert.equal(guard(pair, approved).syntheticFixtureOnly, true);
  for (const [kind, patch] of [
    ["appended-ruby", (x: PairExport) => { x.files[1]!.content += "\n# injected Ruby"; }],
    ["unicode-map", (x: PairExport) => {
      x.files[1]!.content = x.files[1]!.content.replace(
        /(@parserstudio_case_map = JSON.parse\(Zlib::Inflate.inflate\(Base64.strict_decode64\(')([A-Za-z0-9+/=]+)/,
        (_all, prefix: string, encoded: string) => prefix + (encoded[0] === "A" ? "B" : "A") + encoded.slice(1));
    }],
    ["extra-base64", (x: PairExport) => {
      x.files[1]!.content += "\n# Base64.strict_decode64('QUJDREVGR0hJSktM')";
    }],
  ] as const) {
    assert.throws(() => guard(tampered(pair, patch), approved), /POC_RUBY_UNREVIEWED/, kind);
  }
  assert.throws(() => guard(tampered(pair, x => {
    x.files[0]!.content = x.files[0]!.content.replace("bind 127.0.0.1", "bind 0.0.0.0");
  }), approved), /POC_CONF_UNSAFE/);
});

test("the reviewed list is well formed and no production caller overrides it", () => {
  assert.ok(REVIEWED_POC_TEMPLATE_SHA256S.size > 0);
  for (const sha of REVIEWED_POC_TEMPLATE_SHA256S) assert.match(sha, /^[0-9a-f]{64}$/);
  const callers = ["../src/http.ts", "../src/stellar-legacy-client.ts"].flatMap(file => {
    const source = readFileSync(new URL(file, import.meta.url), "utf8");
    return Array.from(source.matchAll(/requireDisposablePocWrite\(([^()]*)\)/g), m => m[1]!.trim());
  });
  assert.ok(callers.length >= 2, "production callers of the writer guard were not found");
  for (const args of callers) assert.equal(args, "plan", "production callers must use the real reviewed list");
});
