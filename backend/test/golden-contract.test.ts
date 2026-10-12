import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

test("synthetic golden event contract covers ten bounded synthetic parser profiles and explicit expected records", () => {
  const fixture = JSON.parse(
    readFileSync(resolve("test_native/fixtures/synthetic-golden.v0.1.json"), "utf8")
  ) as { kind:string; origin:string; cases:Array<{
    id:string; slug:string; raw:string; expectedTime:string|null;
    expectedRecord: Record<string,unknown>;
  }> };
  assert.equal(fixture.kind, "parser-studio.synthetic-golden-events.v0.1");
  assert.equal(fixture.origin, "independently-authored-public-synthetic");
  assert.ok(fixture.cases.length >= 22);
  assert.equal(new Set(fixture.cases.map(value => value.id)).size, fixture.cases.length);
  assert.deepEqual(new Set(fixture.cases.map(value => value.slug)), new Set([
    "sample_firewall", "sample_kv", "sample_extended", "sample_csv",
    "sample_syslog", "sample_syslog_cef", "sample_syslog_leef",
    "sample_cef", "sample_leef", "sample_enriched",
  ]));
  for (const fixtureCase of fixture.cases) {
    assert.match(fixtureCase.id, /^[a-z][a-z0-9_-]+$/);
    assert.match(fixtureCase.slug, /^sample_[a-z]+(?:_[a-z]+)*$/);
    assert.equal(typeof fixtureCase.raw, "string");
    assert.ok(fixtureCase.raw.length <= 16384);
    assert.ok(fixtureCase.expectedRecord && typeof fixtureCase.expectedRecord === "object");
    if (fixtureCase.expectedTime !== null) {
      assert.match(fixtureCase.expectedTime, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    }
  }
});
