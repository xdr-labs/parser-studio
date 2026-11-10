import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error plain ESM helper shared with the authoring test runner
import { rubyRequirementProblem } from "../scripts/ruby-requirement.mjs";

const ruby = (status: number | null, stdout = "") => () => ({ status, stdout });

test("native CI mode fails when Ruby is missing, so Ruby-dependent tests cannot all skip silently", () => {
  assert.match(rubyRequirementProblem({ PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED: "1" }, ruby(null)), /RUBY_REQUIRED_BUT_MISSING/);
  assert.match(rubyRequirementProblem({ PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED: "1" }, ruby(127)), /RUBY_REQUIRED_BUT_MISSING/);
});

test("without the required flag a missing Ruby is not an error (local developer runs)", () => {
  assert.equal(rubyRequirementProblem({}, ruby(null)), undefined);
});

test("a present Ruby passes, and a pinned version must match", () => {
  const ok = { PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED: "1" };
  assert.equal(rubyRequirementProblem(ok, ruby(0, "ruby 3.2.3 (2024)")), undefined);
  const pinned = { ...ok, PARSER_STUDIO_EXPECT_RUBY: "2.4.9" };
  assert.equal(rubyRequirementProblem(pinned, ruby(0, "ruby 2.4.9p362")), undefined);
  assert.match(rubyRequirementProblem(pinned, ruby(0, "ruby 3.2.3 (2024)")), /RUBY_VERSION_MISMATCH/);
});
