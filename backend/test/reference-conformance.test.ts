import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { compilePair } from "../src/index.js";
import {
  CONFORMANCE_RULES,
  checkConfStructure,
  checkFragmentStructure,
  checkPairConformance,
  assertPairConformance,
  parseFluentConf,
} from "../src/reference-conformance.js";
import { sampleProject } from "./fixture.js";

function artifacts() {
  const project = sampleProject();
  const pair = compilePair(project);
  const conf = pair.files.find(file => file.name.endsWith(".conf"))!.content;
  const ruby = pair.files.find(file => !file.name.endsWith(".conf"))!.content;
  return { project, conf, ruby, name: "customized_" + project.slug };
}
const must = (findings: ReturnType<typeof checkFragmentStructure>) =>
  findings.filter(f => f.level === "MUST").map(f => f.rule);

test("real compiled sample satisfies every MUST rule of the Stellar customized-parser structure contract", () => {
  const a = artifacts();
  assert.deepEqual(must(checkFragmentStructure(a.ruby)), []);
  assert.deepEqual(must(checkConfStructure(a.conf, { parserName: a.name })), []);
  assert.deepEqual(checkPairConformance({ parserName: a.name, ruby: a.ruby, conf: a.conf,
    expectedBind: a.project.receiver.bindAddress, protocols: a.project.receiver.protocols,
    classificationIndices: [a.project.classification.defaultIndex, ...a.project.classification.rules.map(r => r.index)] })
    .filter(f => f.level === "MUST"), []);
});

test("code after STELLAR_PARSE_END is rejected, including comments (installed fragments end at the marker)", () => {
  const { ruby } = artifacts();
  assert.deepEqual(must(checkFragmentStructure(ruby + "\n\n")), []);
  assert.deepEqual(must(checkFragmentStructure(ruby + "\n# trailing comment\n")), ["FRAG-NO-CODE-AFTER-PARSE-END"]);
  assert.deepEqual(must(checkFragmentStructure(ruby + "\ndef late_helper\n  1\nend\n")), ["FRAG-NO-CODE-AFTER-PARSE-END"]);
});

test("marker set must be complete, unique and ordered", () => {
  const { ruby } = artifacts();
  assert.ok(must(checkFragmentStructure(ruby.replace("# STELLAR_INIT_END", "# not a marker"))).includes("FRAG-MARKERS"));
  assert.ok(must(checkFragmentStructure(ruby.replace("# STELLAR_PARSE_END", "# STELLAR_PARSE_END\n# STELLAR_PARSE_END"))).includes("FRAG-MARKERS"));
  const swapped = ruby.replace("# STELLAR_PARSE_BEGIN", "# TMP").replace("# STELLAR_INIT_END", "# STELLAR_PARSE_BEGIN").replace("# TMP", "# STELLAR_INIT_END");
  assert.ok(must(checkFragmentStructure(swapped)).includes("FRAG-MARKERS"));
});

test("fragment must not carry wrapper declarations owned by the platform", () => {
  const { ruby } = artifacts();
  for (const decl of ["module Fluent\nend\n", "class StellarInnerParseClass < Parser\nend\n", "Fluent::Plugin.register_parser('x', self)\n"])
    assert.ok(must(checkFragmentStructure(ruby.replace("# STELLAR_INIT_END", decl + "# STELLAR_INIT_END"))).includes("FRAG-NO-WRAPPER-DECLS"), decl);
});

test("executable code between INIT_END and PARSE_BEGIN and before INIT_BEGIN is rejected", () => {
  const { ruby } = artifacts();
  assert.ok(must(checkFragmentStructure(ruby.replace("# STELLAR_PARSE_BEGIN", "puts 1\n# STELLAR_PARSE_BEGIN"))).includes("FRAG-REGION-GAP"));
  assert.ok(must(checkFragmentStructure("puts 1\n" + ruby)).includes("FRAG-REGION-GAP"));
});

test("required methods and error contract are enforced inside their regions", () => {
  const { ruby } = artifacts();
  assert.ok(must(checkFragmentStructure(ruby.replace("def initialize", "def initialise"))).includes("FRAG-INITIALIZE"));
  assert.ok(must(checkFragmentStructure(ruby.replace("def parse(text)", "def parse_text(text)"))).includes("FRAG-PARSE"));
  assert.ok(must(checkFragmentStructure(ruby.split("parser_err_msg").join("parser_failure"))).includes("FRAG-ERROR-CONTRACT"));
  assert.ok(must(checkFragmentStructure(ruby.split("stellar_log_index").join("stellar_idx"))).includes("FRAG-LOG-INDEX"));
});

test("CONF: bind, port, tag, parse type, TCP include and match are checked per source", () => {
  const { conf, name } = artifacts();
  const rules = (text: string, ctx: object = {}) => must(checkConfStructure(text, { parserName: name, ...ctx }));
  const actual = /bind (\S+)/.exec(conf)![1]!;
  assert.deepEqual(rules(conf, { expectedBind: actual }), []);
  assert.ok(rules(conf, { expectedBind: actual === "0.0.0.0" ? "127.0.0.1" : "0.0.0.0" }).includes("CONF-BIND"));
  assert.ok(rules(conf.replace(/bind [0-9.]+/, "bind 10.1.1.1")).includes("CONF-BIND"));
  assert.ok(rules(conf.replace(/port (\d+)/, "port 9")).includes("CONF-PORT-SHARED"));
  assert.ok(rules(conf.replace(/tag customized_\S+/, "tag customized_other")).includes("CONF-TAG"));
  assert.ok(rules(conf.replace(/<parse>\s*@type \S+/, "<parse>\n    @type customized_other")).includes("CONF-PARSE-TYPE"));
  assert.ok(rules(conf.replace("@include /etc/td-agent/transport_settings.conf", "")).includes("CONF-TCP-INCLUDE"));
  assert.ok(rules(conf.replace(/<match [^>]+>/, "<match other.**>")).includes("CONF-MATCH"));
  assert.ok(rules(conf.replace("capitalize_regex_backreference yes", "")).includes("CONF-CAPITALIZE"));
  assert.ok(rules(conf.replace("</match>", "")).includes("CONF-SYNTAX"));
});

test("CONF: classification rules are first-match ordered and end with exactly one inverted syslog guard", () => {
  const { name } = artifacts();
  const base = (rulesBlock: string) => [
    "<source>\n  @type udp\n  port 6801\n  bind 0.0.0.0\n  tag " + name + "\n  <parse>\n    @type " + name + "\n  </parse>\n</source>",
    "<match " + name + ".**>\n  @type rewrite_tag_filter\n  capitalize_regex_backreference yes\n" + rulesBlock + "</match>\n",
  ].join("\n\n");
  const rule = (pattern: string, tag: string, invert = false, key = "stellar_log_index") =>
    "  <rule>\n    key " + key + "\n    pattern " + pattern + "\n    tag " + tag + (invert ? "\n    invert true" : "") + "\n  </rule>\n";
  const run = (block: string) => must(checkConfStructure(base(block), { parserName: name }));
  assert.deepEqual(run(rule("/^session$/", "session") + rule("/^(?:session)$/", "syslog", true)), []);
  assert.deepEqual(run(rule("/session/", "session") + rule("/session/", "syslog", true)), []);
  assert.deepEqual(run(rule("/^$/", "syslog", true)), []);
  assert.ok(run(rule("/^(?:session)$/", "syslog", true) + rule("/^session$/", "session")).includes("CONF-RULE-ORDER"));
  assert.ok(run(rule("/^session$/", "session")).includes("CONF-RULE-ORDER"));
  assert.ok(run(rule("/^session$/", "session", false, "other_key") + rule("/^(?:session)$/", "syslog", true)).includes("CONF-RULE-KEY"));
  assert.ok(run(rule("/^session$/", "session") + rule("/^(?:session|syslog)$/", "syslog", true)).includes("CONF-RULE-ORDER"));
  assert.ok(run(rule("/^thr$/", "threat") + rule("/^(?:threat)$/", "syslog", true)).includes("CONF-RULE-ORDER"));
});

test("CONF parser reads nested sections, parameters and @include without executing anything", () => {
  const tree = parseFluentConf("# c\n<source>\n  @type tcp\n  <parse>\n    @type x\n  </parse>\n  @include /a/b.conf\n</source>\n");
  assert.equal(tree.errors.length, 0);
  assert.equal(tree.root.children[0]!.name, "source");
  assert.equal(tree.root.children[0]!.children[0]!.params.find(p => p.key === "@type")!.value, "x");
  assert.deepEqual(tree.root.children[0]!.includes, ["/a/b.conf"]);
  assert.ok(parseFluentConf("<source>\n").errors.length > 0);
  assert.ok(parseFluentConf("</source>\n").errors.length > 0);
});

test("pair-level naming and classification coverage are checked", () => {
  const a = artifacts();
  const ctx = { parserName: a.name, ruby: a.ruby, conf: a.conf, expectedBind: a.project.receiver.bindAddress,
    protocols: a.project.receiver.protocols, classificationIndices: ["syslog", "threat", "session", "winlogevent"] as string[] };
  assert.ok(checkPairConformance(ctx).some(f => f.rule === "PAIR-CLASSIFICATION-ROUTES" && f.level === "MUST"),
    "a class the parser can emit needs a CONF route");
  assert.ok(checkPairConformance({ ...ctx, protocols: ["udp"] }).some(f => f.rule === "PAIR-PROTOCOLS"));
});

test("assertPairConformance fails closed with every violated MUST rule", () => {
  const a = artifacts();
  assert.throws(() => assertPairConformance({ parserName: a.name, ruby: a.ruby + "\ndef late\nend\n", conf: a.conf,
    expectedBind: a.project.receiver.bindAddress, protocols: a.project.receiver.protocols,
    classificationIndices: ["syslog"] }), /FRAG-NO-CODE-AFTER-PARSE-END/);
});

test("contract descriptor and code rules are the same set, with corpus provenance and no installed bytes", () => {
  const descriptor = JSON.parse(readFileSync(new URL("../../contracts/stellar-custom-parser-structure.v1.json", import.meta.url), "utf8"));
  assert.equal(descriptor.contract, "stellar-custom-parser-structure.v1");
  const declared = descriptor.rules.map((r: { id: string }) => r.id).sort();
  assert.deepEqual(declared, CONFORMANCE_RULES.map(r => r.id).sort());
  for (const rule of descriptor.rules) {
    assert.ok(["MUST", "SHOULD", "INFO"].includes(rule.level), rule.id);
    assert.ok(typeof rule.referenceEvidence === "string" && rule.referenceEvidence.length > 0, rule.id + " needs evidence");
  }
  assert.equal(descriptor.provenance.hostChanged, false);
  assert.ok(!JSON.stringify(descriptor).includes("def initialize"), "installed parser source must never be copied into the repository");
});

// Every rule of the contract must have a mutation that makes exactly that rule
// fire at its declared level. A rule added to CONFORMANCE_RULES without a
// mutation here fails the key-set assertion, so no rule can exist untested.
test("every conformance rule has a mutation that triggers it at its declared level", () => {
  const a = artifacts();
  const fragment = (ruby: string) => checkFragmentStructure(ruby);
  const conf = (text: string) => checkConfStructure(text, { parserName: a.name });
  const pair = (over: object) => checkPairConformance({ parserName: a.name, ruby: a.ruby, conf: a.conf,
    expectedBind: a.project.receiver.bindAddress, protocols: a.project.receiver.protocols,
    classificationIndices: [a.project.classification.defaultIndex], ...over });
  const mutations: Record<string, () => ReturnType<typeof checkFragmentStructure>> = {
    "FRAG-MARKERS": () => fragment(a.ruby.replace("# STELLAR_INIT_END", "# not a marker")),
    "FRAG-NO-CODE-AFTER-PARSE-END": () => fragment(a.ruby + "\ndef late\nend\n"),
    "FRAG-REGION-GAP": () => fragment(a.ruby.replace("# STELLAR_PARSE_BEGIN", "puts 1\n# STELLAR_PARSE_BEGIN")),
    "FRAG-NO-WRAPPER-DECLS": () => fragment(a.ruby.replace("# STELLAR_INIT_END", "module Fluent\nend\n# STELLAR_INIT_END")),
    "FRAG-INITIALIZE": () => fragment(a.ruby.replace("def initialize", "def initialise")),
    "FRAG-RULESET": () => fragment(a.ruby.split("@parser_rule_set").join("@parser_rules")),
    "FRAG-PARSE": () => fragment(a.ruby.replace("def parse(text)", "def parse_text(text)")),
    "FRAG-YIELD": () => fragment(a.ruby.replace(/\byield\b/g, "emit")),
    "FRAG-ERROR-CONTRACT": () => fragment(a.ruby.split("parser_err_msg").join("parser_failure")),
    "FRAG-LOG-INDEX": () => fragment(a.ruby.split("stellar_log_index").join("stellar_idx")),
    "FRAG-EMPTY-INPUT": () => fragment(a.ruby.replace(/yield\s+nil\s*,\s*nil/g, "return")),
    "CONF-SYNTAX": () => conf(a.conf.replace("</match>", "")),
    "CONF-SOURCE-TYPES": () => conf(a.conf.replace("@type udp", "@type http")),
    "CONF-BIND": () => conf(a.conf.replace(/bind [0-9.]+/, "bind 10.1.1.1")),
    "CONF-PORT-SHARED": () => conf(a.conf.replace(/port (\d+)/, "port 9")),
    "CONF-TAG": () => conf(a.conf.replace(/tag customized_\S+/, "tag customized_other")),
    "CONF-PARSE-TYPE": () => conf(a.conf.replace(/<parse>\s*@type \S+/, "<parse>\n    @type customized_other")),
    "CONF-TCP-INCLUDE": () => conf(a.conf.replace("@include /etc/td-agent/transport_settings.conf", "")),
    "CONF-MATCH": () => conf(a.conf.replace(/<match [^>]+>/, "<match other.**>")),
    "CONF-CAPITALIZE": () => conf(a.conf.replace("capitalize_regex_backreference yes", "")),
    "CONF-RULE-KEY": () => conf(a.conf.replace("key stellar_log_index", "key other_key")),
    "CONF-RULE-ORDER": () => conf(a.conf.replace("invert true", "")),
    "PAIR-PROTOCOLS": () => pair({ protocols: ["udp"] }),
    "PAIR-CLASSIFICATION-ROUTES": () => pair({ classificationIndices: ["syslog", "threat", "session", "winlogevent"] }),
  };
  assert.deepEqual(Object.keys(mutations).sort(), CONFORMANCE_RULES.map(r => r.id).sort(),
    "every rule needs exactly one mutation, and every mutation a rule");
  for (const rule of CONFORMANCE_RULES) {
    const found = mutations[rule.id]!().filter(f => f.rule === rule.id);
    assert.ok(found.length > 0, rule.id + " is never triggered by its mutation");
    assert.ok(found.every(f => f.level === rule.level), rule.id + " fires at the wrong level");
  }
  // The unmutated sample must be completely clean, including SHOULD rules.
  assert.deepEqual([...fragment(a.ruby), ...conf(a.conf), ...pair({})], []);
});

// MUST in the contract means "Parser Studio output must satisfy it" and is
// enforced fail-closed. The corpus frequency alone does not justify that, so each
// rule declares why it is MUST: invariant in the corpus, or a product rule whose
// corpus exceptions are explained. SHOULD is reserved for >=95% practice.
test("contract MUST/SHOULD levels agree with the declared corpus basis and numbers", () => {
  const descriptor = JSON.parse(readFileSync(new URL("../../contracts/stellar-custom-parser-structure.v1.json", import.meta.url), "utf8"));
  const levels = new Map(CONFORMANCE_RULES.map(r => [r.id, r.level] as const));
  for (const rule of descriptor.rules as Array<{ id: string; level: string; basis?: string; corpus?: { matching: number; total: number }; justification?: string; referenceEvidence: string }>) {
    assert.equal(rule.level, levels.get(rule.id), rule.id + " level differs between contract and checker");
    assert.ok(["corpus-invariant", "corpus-practice", "product-rule"].includes(rule.basis ?? ""), rule.id + " needs a basis");
    if (rule.basis === "product-rule") {
      assert.equal(rule.level, "MUST", rule.id + ": a product rule is enforced as MUST");
      assert.ok((rule.justification ?? "").length >= 20, rule.id + " needs a justification");
    }
    if (rule.corpus) {
      const { matching, total } = rule.corpus;
      assert.ok(Number.isInteger(matching) && Number.isInteger(total) && matching <= total && total > 0, rule.id);
      assert.ok(rule.referenceEvidence.includes(matching + "/" + total), rule.id + " evidence text must quote " + matching + "/" + total);
      if (rule.basis === "corpus-invariant") { assert.equal(matching, total, rule.id); assert.equal(rule.level, "MUST", rule.id); }
      if (rule.basis === "corpus-practice") { assert.equal(rule.level, "SHOULD", rule.id); assert.ok(matching / total >= 0.95 && matching < total, rule.id); }
      if (rule.basis === "product-rule" && matching === total) assert.fail(rule.id + " is corpus-invariant, not a product rule");
    } else {
      assert.equal(rule.basis, "product-rule", rule.id + ": a rule without corpus numbers is a product rule");
    }
  }
});
