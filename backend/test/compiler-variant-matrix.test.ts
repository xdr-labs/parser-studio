import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { compilePair, validateProject } from "../src/index.js";
import { checkPairConformance } from "../src/reference-conformance.js";
import { compilerVariants } from "./compiler-variants.js";

const root = (path: string) => new URL("../../" + path, import.meta.url);
const coverage = JSON.parse(readFileSync(root("contracts/execution-coverage.v1.json"), "utf8"));
const split = (pair: ReturnType<typeof compilePair>) => ({
  conf: pair.files.find(f => f.name.endsWith(".conf"))!.content,
  ruby: pair.files.find(f => !f.name.endsWith(".conf"))!,
});

test("every enumerated compiler variant is a valid project (the matrix cannot silently rot)", () => {
  for (const variant of compilerVariants()) {
    const result = validateProject(variant.project);
    assert.equal(result.ok, true, variant.id + ": " + JSON.stringify(result.ok ? [] : result.issues));
  }
});

test("every compiler variant yields a fragment+CONF pair that satisfies the Stellar structure contract", () => {
  const failures: string[] = [];
  for (const variant of compilerVariants()) {
    const p = variant.project;
    let findings;
    try {
      const { conf, ruby } = split(compilePair(p));
      findings = checkPairConformance({
        parserName: ruby.name, ruby: ruby.content, conf, expectedBind: p.receiver.bindAddress,
        protocols: p.receiver.protocols,
        classificationIndices: [p.classification.defaultIndex, ...p.classification.rules.map(r => r.index)],
      });
    } catch (error) {
      failures.push(variant.id + " => " + String(error instanceof Error ? error.message.slice(0, 160) : error));
      continue;
    }
    const musts = findings.filter(f => f.level === "MUST");
    if (musts.length) failures.push(variant.id + " => " + musts.map(f => f.rule).join(","));
  }
  assert.deepEqual(failures, []);
});

test("the variant matrix covers every extraction format, template family and enrichment operator named by the coverage contract", () => {
  const variants = compilerVariants();
  const formats = new Set(variants.map(v => v.project.extraction.format));
  for (const format of coverage.extractionFormats) assert.ok(formats.has(format), "no variant for format " + format);
  const family = (p: typeof variants[number]["project"]) => Boolean(p.extraction.forwarder || p.normalization.eventProfiles);
  assert.ok(variants.some(v => !family(v.project)), "no ordinary-template variant");
  assert.ok(variants.some(v => family(v.project)), "no family-template variant");
  const operators = new Set(variants.flatMap(v => (v.project.enrichment ?? []).map(step => step.operator)));
  for (const operator of coverage.operators) assert.ok(operators.has(operator), "no variant for operator " + operator);
  const binds = new Set(variants.map(v => v.project.receiver.bindAddress));
  assert.deepEqual([...binds].sort(), ["0.0.0.0", "127.0.0.1"]);
  const classes = new Set<string>(variants.flatMap(v => [v.project.classification.defaultIndex, ...v.project.classification.rules.map(r => r.index)]));
  for (const index of ["syslog", "threat", "session", "winlogevent"]) assert.ok(classes.has(index), "no variant routes " + index);
});

test("the project schema cannot gain an extraction format that coverage and the matrix do not know", () => {
  const schema = JSON.parse(readFileSync(root("backend/schema/parser-project.v0.1.schema.json"), "utf8"));
  const text = JSON.stringify(schema);
  const enumFormats: string[] = schema.properties?.extraction?.properties?.format?.enum
    ?? JSON.parse(text.slice(text.indexOf('"json","kv","csv"') - 1).replace(/^\[/, "[").slice(0, text.slice(text.indexOf('"json","kv","csv"') - 1).indexOf("]") + 1));
  assert.deepEqual([...enumFormats].sort(), [...coverage.extractionFormats].sort());
});

test("compiler.ts never appends code after the PARSE_END marker; helpers go through insertBeforeParseEnd", () => {
  const source = readFileSync(new URL("../src/compiler.ts", import.meta.url), "utf8");
  const appended = source.split("\n").filter(line => /\bfragment\s*\+=/.test(line));
  assert.deepEqual(appended, [], "use insertBeforeParseEnd(fragment, helper) instead of fragment+=");
});

test("compilePair itself is fail-closed on the structure contract (new generation paths cannot ship non-conforming files)", async () => {
  const { assertCompiledPairConformance } = await import("../src/compiler.js");
  const { sampleProject } = await import("./fixture.js");
  const project = sampleProject();
  const pair = compilePair(project);
  const conf = pair.files.find(f => f.name.endsWith(".conf"))!.content;
  const ruby = pair.files.find(f => !f.name.endsWith(".conf"))!.content;
  assert.doesNotThrow(() => assertCompiledPairConformance(project, conf, ruby));
  assert.throws(() => assertCompiledPairConformance(project, conf, ruby + "\ndef shipped_after_marker\nend\n"), /FRAG-NO-CODE-AFTER-PARSE-END/);
  assert.throws(() => assertCompiledPairConformance(project, conf.replace("bind 0.0.0.0", "bind 192.0.2.1"), ruby), /CONF-BIND/);
});
