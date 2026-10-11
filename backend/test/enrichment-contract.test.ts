import assert from "node:assert/strict";
import test from "node:test";
import { compilePair, validateProject } from "../src/index.js";
import { sampleProject } from "./fixture.js";

test("allowlisted no-code enrichments are accepted without any Ruby source input", () => {
  const p = sampleProject();
  p.enrichment = [
    { operator: "set_const", target: "log.source_label", value: "synthetic" },
    { operator: "lowercase", source: "action", target: "log.action_lower" },
    { operator: "copy", source: "srcip", target: "log.original_srcip" },
    { operator: "uppercase", source: "log.action_lower", target: "log.action_upper" },
  ];
  assert.deepEqual(validateProject(p).issues, []);
  assert.equal(compilePair(p).files.length, 2);
});

test("reject source-code injection, invalid destination, missing source, collision and unsupported operator", () => {
  const patterns: Array<(p: any) => void> = [
    p => { p.enrichment = [{ operator: "ruby_eval", target: "x", value: "Kernel.exit" }]; },
    p => { p.enrichment = [{ operator: "set_const", target: "parser_err_msg", value: "oops" }]; },
    p => { p.enrichment = [{ operator: "set_const", target: "__proto__.evil", value: "oops" }]; },
    p => { p.enrichment = [{ operator: "copy", source: "does_not_exist", target: "log.copy" }]; },
    p => { p.enrichment = [{ operator: "set_const", target: "srcip", value: "bad" }]; },
    p => { p.enrichment = [{ operator: "lowercase", source: "srcip", target: "log.copy", value: "unsupported" }]; },
    p => { p.enrichment = [{ operator: "set_const", target: "log.copy", value: "a" },{ operator: "set_const", target: "log.copy", value: "b" }]; },
  ];
  for (const mutate of patterns) {
    const p: any = sampleProject(); mutate(p);
    assert.equal(validateProject(p).ok, false, JSON.stringify(p.enrichment));
  }
});

test("enrichment output is deterministic and retained in generated encoded model", () => {
  const p = sampleProject();
  p.enrichment = [{ operator: "set_const", target: "vendor.parser_profile", value: "fixture1" }];
  const fragment = compilePair(p).files[1]!.content;
  const b64 = fragment.match(/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/)?.[1];
  assert.ok(b64);
  const recovered = JSON.parse(Buffer.from(b64!, "base64").toString("utf8")) as Record<string, any>;
  assert.equal(recovered.enrichment[0].value, "fixture1");
});
