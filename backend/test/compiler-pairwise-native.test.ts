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
  /** Mixed extraction only: the same event in the second declared format (the first is `line`). */
  alt?: (ip: string, action: "deny" | "allow") => string;
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
  "mixed-json-kv": { extraction: { format: "mixed", mixedFormats: ["json", "kv"] }, src: "srcip", act: "action", line: (ip, a) => JSON.stringify({ srcip: ip, action: a }), alt: (ip, a) => "srcip=" + ip + " action=" + a },
  "mixed-json-csv": { extraction: { format: "mixed", mixedFormats: ["json", "csv"], csvColumns: ["srcip", "action", "charlie"], csvDelimiter: "," }, src: "srcip", act: "action", line: (ip, a) => JSON.stringify({ srcip: ip, action: a }), alt: (ip, a) => ip + "," + a + ",x" },
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

test("every pairwise variant emits the authored values on this runtime (Regex too: bounded Regex executes natively, with or without a Regexp timeout)", { skip: !available }, () => {
  const rubyVersion = parsedRubyVersion(spawnSync("ruby", ["-v"], { encoding: "utf8" }).stdout);
  const profiles = JSON.parse(readFileSync(new URL("../../contracts/target-runtime-profiles.v1.json", import.meta.url), "utf8")) as {
    profiles: { ruby: string; regexDeadlineCapable: boolean }[];
    unsupported: { feature: string; profile: string; behavior: string }[];
  };
  const profile = profiles.profiles.find(item => item.ruby === rubyVersion);
  // The pinned target step sets PARSER_STUDIO_EXPECT_RUBY: there the interpreter
  // must be a declared profile. A plain host run (for example the CI runner's
  // current Ruby) has no declared profile and is judged by what it can do.
  if (process.env.PARSER_STUDIO_EXPECT_RUBY) assert.ok(profile, "pinned native runtime must have an explicit target profile: " + rubyVersion);
  // Ask the interpreter instead of inferring from the version number: Regexp
  // deadlines exist from Ruby 3.2, and a declared profile must agree with it.
  const probe = spawnSync("ruby", ["-e", "print(Regexp.respond_to?(:timeout) ? 'capable' : 'incapable')"], { encoding: "utf8", timeout: 3000 });
  assert.equal(probe.status, 0, "Regexp deadline probe failed: " + String(probe.stderr).slice(0, 200));
  const regexDeadlineCapable = probe.stdout === "capable";
  if (profile) assert.equal(profile.regexDeadlineCapable, regexDeadlineCapable,
    "declared regexDeadlineCapable for Ruby " + rubyVersion + " must match the interpreter");
  let checked = 0;
  let regexExecuted = 0;
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
        // Each family maps the same source to its own vendor field, so a skipped or
        // wrong profile selection changes the asserted output.
        { name: "allow", equals: "allow", topFields: {}, nsFields: {}, vendorFields: { [fixture.src]: { normalized_name: "allow_src", data_type: "ip" } } },
        { name: "deny", equals: "deny", topFields: {}, nsFields: {}, vendorFields: { [fixture.src]: { normalized_name: "deny_src", data_type: "ip" } } },
      ],
    };
    const valid = validateProject(p);
    assert.equal(valid.ok, true, variant.id + " " + JSON.stringify(valid.issues));
    // Under a declared relay the second log arrives wrapped by relay01 (one hop);
    // it must yield the same event plus exactly one recorded hop.
    const wrap = (raw: string, position: number) => relayed && position === 1 ? "<134>Jan 16 15:19:05 relay01 fw: " + raw : raw;
    // A mixed extraction receives its first declared format at position 0 and its second
    // at position 1, so every branch of mixedFormats is executed and judged.
    const raws = [fixture.line("192.0.2.10", "deny"), (fixture.alt ?? fixture.line)("192.0.2.11", "allow")];
    const events = run(p, raws.map(wrap));
    assert.equal(events.length, 2, variant.id + ": one event per raw log");
    for (const [position, action, ip] of [[0, "deny", "192.0.2.10"], [1, "allow", "192.0.2.11"]] as const) {
      const e = events[position]!;
      const where = variant.id + " #" + position;
      // Ruby 2.4.9 (Stellar 7.0) has no Regexp timeout. The fixture pattern passed
      // the generation-time static cost classification, so it must execute
      // natively and yield the authored values, exactly as on a timeout-capable Ruby.
      if (level("extraction") === "regex") regexExecuted += 1;
      if (relayed) assert.equal(e.parserstudio_transport?.forwarder_hops?.length ?? 0, position, where + " relay hops");
      assert.equal(e.srcip, ip, where + " srcip");
      assert.equal(e.action, action, where + " action");
      if (level("event-profiles") === "two-families") {
        const other = action === "deny" ? "allow" : "deny";
        assert.equal(e.parserstudio_event_family, action, where + " selected event family");
        assert.equal(e.Synthetic?.[action + "_src"], ip, where + " mapping of the selected family");
        assert.equal(e.Synthetic?.[other + "_src"], undefined, where + " mapping of the other family leaked");
      } else assert.equal(e.parserstudio_event_family, undefined, where + " family without event profiles");
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
      assert.ok(!JSON.stringify(copy).includes(raws[position]!), where + " raw log leaked into the event");
    }
    checked += 1;
  }
  assert.equal(checked, pairwiseVariants().length, "every pairwise variant must be executed, none skipped");
  assert.ok(checked >= 40, "too few pairwise variants executed: " + checked);
  assert.ok(regexExecuted > 0, "Regex variants must be executed, not skipped");
  if (!regexDeadlineCapable) {
    const target = JSON.parse(readFileSync(new URL("../../contracts/target-runtime-profiles.v1.json", import.meta.url), "utf8")) as
      { supported: { feature: string; behavior: string }[]; unsupported: { feature: string; behavior: string }[] };
    assert.ok(target.supported.some(item => item.feature === "regex-bounded" && item.behavior === "NATIVE_EXECUTION_STATIC_COST_PROOF"),
      "a runtime without Regexp timeout must declare its bounded-Regex proof basis");
    assert.ok(target.unsupported.some(item => item.feature === "regex-unbounded" && item.behavior === "FAIL_CLOSED_RUNTIME"),
      "a runtime without Regexp timeout must declare unbounded Regex as fail-closed");
  }
  process.stdout.write("PAIRWISE_NATIVE executed=" + checked + " regex_executed=" + regexExecuted + " regexp_timeout_capable=" + regexDeadlineCapable + "\n");
});
