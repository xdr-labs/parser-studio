// Behaviour check for the pairwise Compiler variants (compiler-pairwise.ts): the
// generated Ruby is executed on authored raw logs and must emit the authored
// values. Structure conformance (compiler-variant-matrix.test.ts) says the file
// has the right shape; this says it parses the right way for that combination of
// extraction, enrichment, classification and event profiles.
//
// Expectations are written by hand from each format's grammar and from the
// declared classification rules; none is read back from Ruby output. Synthetic
// logs only. Not a Stellar Cyber import, Syslog reception or indexing result.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { compilePair } from "../src/compiler.js";
import { validateProject } from "../src/validate.js";
import type { ParserProject } from "../src/types.js";
import { pairwiseVariants } from "./compiler-pairwise.js";
// @ts-expect-error plain ESM helper shared with the authoring test runner
import { parsedRubyVersion } from "../scripts/ruby-requirement.mjs";

interface Fixture {
  extraction: ParserProject["extraction"];
  src: string; act: string;
  line: (ip: string, action: "deny" | "allow") => string;
}
const FIXTURES: Record<string, Fixture> = {
  json: { extraction: { format: "json" }, src: "srcip", act: "action", line: (ip, a) => JSON.stringify({ srcip: ip, action: a }) },
  kv: { extraction: { format: "kv" }, src: "srcip", act: "action", line: (ip, a) => "srcip=" + ip + " action=" + a },
  cef: { extraction: { format: "cef" }, src: "src", act: "act", line: (ip, a) => "CEF:0|Acme|Edge|1.0|100|Threat|7|src=" + ip + " act=" + a },
  leef: { extraction: { format: "leef" }, src: "src", act: "action", line: (ip, a) => "LEEF:2.0|Acme|Edge|1.0|100|^|src=" + ip + "^action=" + a },
  csv: { extraction: { format: "csv", csvColumns: ["alpha", "bravo", "charlie"], csvDelimiter: "," }, src: "alpha", act: "bravo", line: (ip, a) => ip + "," + a + ",x" },
  regex: { extraction: { format: "regex", pattern: String.raw`^src=(?<srcip>[\d.]+) action=(?<action>deny|allow)$` }, src: "srcip", act: "action", line: (ip, a) => "src=" + ip + " action=" + a },
  "rfc3164-kv": { extraction: { format: "syslog_rfc3164", syslogBodyFormat: "kv" }, src: "body.srcip", act: "body.action", line: (ip, a) => "<134>Nov  7 12:00:00 edge01 app: srcip=" + ip + " action=" + a },
  "rfc5424-json": { extraction: { format: "syslog_rfc5424", syslogBodyFormat: "json" }, src: "body.srcip", act: "body.action", line: (ip, a) => "<134>1 2026-11-07T12:00:00Z edge01 app - ID - " + JSON.stringify({ srcip: ip, action: a }) },
  "mixed-json-kv": { extraction: { format: "mixed", mixedFormats: ["json", "kv"] }, src: "srcip", act: "action", line: (ip, a) => JSON.stringify({ srcip: ip, action: a }) },
  "mixed-json-csv": { extraction: { format: "mixed", mixedFormats: ["json", "csv"], csvColumns: ["srcip", "action", "charlie"], csvDelimiter: "," }, src: "srcip", act: "action", line: (ip, a) => JSON.stringify({ srcip: ip, action: a }) },
  generic: { extraction: { format: "generic_structural" }, src: "generic.kv.srcip", act: "generic.kv.action", line: (ip, a) => "srcip=" + ip + " action=" + a + " proto=tcp aa=1 bb=2" },
};

const available = spawnSync("ruby", ["-v"], { encoding: "utf8", timeout: 3000 }).status === 0;
const required = process.env.PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED === "1";

function run(project: ParserProject, lines: string[]): Array<Record<string, any>> {
  const code = compilePair(project).files.find(f => !f.name.endsWith(".conf"))!.content;
  const harness = [
    "require 'json'", "require 'base64'", "require 'date'", "require 'time'", "require 'csv'", "require 'ipaddr'",
    "klass=Class.new", "klass.class_eval(Base64.strict_decode64(STDIN.gets.strip),'pairwise-native',1)",
    "parser=klass.new", "rows=[]",
    "JSON.parse(STDIN.read).each{|line| parser.parse(line){|_time,record|rows << record}}",
    "STDOUT.write(JSON.generate(rows))",
  ].join("\n");
  const result = spawnSync("ruby", ["-e", harness], {
    encoding: "utf8", timeout: 20000, maxBuffer: 1024 * 1024,
    input: Buffer.from(code, "utf8").toString("base64") + "\n" + JSON.stringify(lines),
  });
  assert.equal(result.status, 0, "generated Ruby failed: " + String(result.stderr).slice(0, 200));
  return JSON.parse(result.stdout);
}

// First matching declared rule wins; otherwise the default index.
const indexFor = (level: string, action: "deny" | "allow"): string =>
  level === "syslog-only" ? "syslog" : level === "threat-default" ? "threat" : action === "deny" ? "threat" : "session";

test("pairwise variants are checked on a Ruby runtime (a missing Ruby must not read as a pass)", () => {
  if (required) assert.equal(available, true, "native CI requires Ruby");
  // The target-runtime CI step pins the interpreter (2.4.9) so a shim that fell
  // back to the host Ruby cannot pass as the target.
  const expected = process.env.PARSER_STUDIO_EXPECT_RUBY;
  if (expected) assert.equal(parsedRubyVersion(spawnSync("ruby", ["-v"], { encoding: "utf8" }).stdout), expected, "native Ruby interpreter version must exactly match the pinned profile");
});

test("every pairwise variant emits documented target behavior (including unsupported Regex fail-closed)", { skip: !available }, () => {
  const rubyVersion = parsedRubyVersion(spawnSync("ruby", ["-v"], { encoding: "utf8" }).stdout);
  const profiles = JSON.parse(readFileSync(new URL("../../contracts/target-runtime-profiles.v1.json", import.meta.url), "utf8")) as {
    profiles: { ruby: string; regexDeadlineCapable: boolean }[];
    unsupported: { feature: string; profile: string; behavior: string }[];
  };
  const profile = profiles.profiles.find(item => item.ruby === rubyVersion);
  assert.ok(profile, "native runtime must have an explicit target profile: " + rubyVersion);
  let checked = 0;
  let regexClosed = 0;
  for (const variant of pairwiseVariants()) {
    const level = (name: string) => variant.levels.find(l => l.startsWith(name + "="))!.split("=")[1]!;
    const relayed = level("forwarder") === "relay";
    const fixture = FIXTURES[level("extraction")];
    assert.ok(fixture, "no authored fixture for extraction level " + level("extraction"));
    const p = structuredClone(variant.project);
    p.extraction = relayed ? { ...fixture.extraction, forwarder: variant.project.extraction.forwarder } : fixture.extraction;
    p.normalization.topFields = {
      [fixture.src]: { normalized_name: "srcip", data_type: "ip" },
      [fixture.act]: { normalized_name: "action", data_type: "string" },
    };
    // The authored logs carry no destination address, so a rule on dstip cannot be
    // exercised (and would not validate): winlogevent routing is checked by
    // structure only. Every other declared rule is kept.
    p.classification = { ...p.classification, rules: p.classification.rules.filter(rule => rule.field !== "dstip") };
    p.normalization.nsFields = {};
    p.normalization.vendorFields = {};
    if (p.normalization.eventProfiles) p.normalization.eventProfiles = {
      discriminator: fixture.act, unknown: "reject", variants: [
        { name: "allow", equals: "allow", topFields: {}, nsFields: {}, vendorFields: {} },
        { name: "deny", equals: "deny", topFields: {}, nsFields: {}, vendorFields: {} },
      ],
    };
    const valid = validateProject(p);
    assert.equal(valid.ok, true, variant.id + " " + JSON.stringify(valid.issues));
    // Under a declared relay the second log arrives wrapped by relay01 (one hop);
    // it must yield the same event plus exactly one recorded hop.
    const wrap = (raw: string, position: number) => relayed && position === 1 ? "<134>Jan 16 15:19:05 relay01 fw: " + raw : raw;
    const events = run(p, [wrap(fixture.line("192.0.2.10", "deny"), 0), wrap(fixture.line("192.0.2.11", "allow"), 1)]);
    assert.equal(events.length, 2, variant.id + ": one event per raw log");
    for (const [position, action, ip] of [[0, "deny", "192.0.2.10"], [1, "allow", "192.0.2.11"]] as const) {
      const e = events[position]!;
      const where = variant.id + " #" + position;
      // Stellar 7.0 observed Ruby 2.4.9 has no Regexp timeout. The Compiler
      // MUST fail closed at extraction instead of returning an unsafe match.
      // This is a target capability contract, not an exempted/untested case.
      if (level("extraction") === "regex" && !profile.regexDeadlineCapable) {
        assert.equal(e.parser_err_stage, "extraction", where + " unsupported regex stage");
        assert.equal(e.parser_err_msg, "ArgumentError", where + " unsupported regex diagnostic");
        assert.equal(e.stellar_log_index, "syslog", where + " unsupported regex index");
        assert.equal(e.srcip, undefined, where + " unsafe regex emitted srcip");
        assert.equal(e.action, undefined, where + " unsafe regex emitted action");
        assert.equal(e.parserstudio_transport, undefined, where + " failed extraction leaked relay metadata");
        regexClosed += 1;
        continue;
      }
      if (relayed) assert.equal(e.parserstudio_transport?.forwarder_hops?.length ?? 0, position, where + " relay hops");
      assert.equal(e.srcip, ip, where + " srcip");
      assert.equal(e.action, action, where + " action");
      if (level("enrichment") === "split_field") {
        // The authored action ("deny"/"allow") has no ":" to split on, so the
        // canonical operator contract (CANONICAL_OPERATOR_CONTRACT_V1.enrichment)
        // applies: the whole enrichment transaction rolls back, the failure is
        // reported at the enrichment stage on the source field, and only the
        // already validated fields stay.
        assert.equal(e.parser_err_stage, "enrichment", where + " split_field failure stage");
        assert.equal(e.parser_err_field, "action", where + " split_field failure field");
        assert.ok(!e.log?.action_head && !e.log?.action_tail, where + " split_field wrote after a failed transaction");
        continue;
      }
      assert.equal(e.parser_err_stage, undefined, where + " unexpected parser error " + e.parser_err_stage);
      assert.equal(e.stellar_log_index, indexFor(level("classification"), action), where + " routing");
      if (level("enrichment") === "set_const") assert.equal(e.log?.constant, "fixed", where + " set_const");
      if (level("enrichment") === "copy") assert.equal(e.log?.action_copy, action, where + " copy");
      // Generic Structural deliberately keeps the whole line as source evidence at
      // parserstudio_source.generic.source_raw unless omitSourceRaw is set. It must
      // be the only place the raw log appears; every other extraction keeps it out.
      const copy = structuredClone(e);
      if (level("extraction") === "generic") delete copy.parserstudio_source?.generic?.source_raw;
      assert.ok(!JSON.stringify(copy).includes(fixture.line(ip, action)), where + " raw log leaked into the event");
    }
    checked += 1;
  }
  assert.equal(checked, pairwiseVariants().length, "every pairwise variant must be executed, none skipped");
  assert.ok(checked >= 40, "too few pairwise variants executed: " + checked);
  if (!profile.regexDeadlineCapable) {
    assert.ok(regexClosed > 0, "unsupported Regex target must execute and reject real negative controls");
    assert.ok(profiles.unsupported.some(item => item.feature === "regex" && item.behavior === "FAIL_CLOSED_RUNTIME"),
      "unsupported regex target must have an explicit declared fail-closed contract");
  } else assert.equal(regexClosed, 0);
  process.stdout.write("PAIRWISE_NATIVE executed=" + checked + " regex_rejected_for_unsupported_target=" + regexClosed + "\n");
});
