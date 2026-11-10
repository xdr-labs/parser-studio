// Reference Parser Conformance Gate.
//
// Encodes the structure contract observed (read-only) in the Stellar Cyber
// custom parsers installed on the reference host and recorded in
// contracts/stellar-custom-parser-structure.v1.json. The checks are pure text
// and configuration-structure checks: nothing here executes Ruby or Fluentd,
// and none of the installed parser source is reproduced. Ruby syntax, Ruby 2.4
// execution and AST-level checks are the job of the container gate.
//
// Levels: MUST = observed in every reference artifact of the same kind (or
// required by the wrapper contract) and enforced fail-closed; SHOULD = observed
// in the large majority and reported; the descriptor lists the evidence.

export type ConformanceLevel = "MUST" | "SHOULD";
export interface ConformanceFinding { rule: string; level: ConformanceLevel; message: string }
export interface ConformanceRule { id: string; level: ConformanceLevel; scope: "fragment" | "conf" | "pair"; description: string }

export const CONFORMANCE_RULES: readonly ConformanceRule[] = [
  { id: "FRAG-MARKERS", level: "MUST", scope: "fragment", description: "STELLAR_INIT_BEGIN, INIT_END, PARSE_BEGIN and PARSE_END each occur exactly once, in that order." },
  { id: "FRAG-NO-CODE-AFTER-PARSE-END", level: "MUST", scope: "fragment", description: "Nothing but blank lines follows STELLAR_PARSE_END." },
  { id: "FRAG-REGION-GAP", level: "MUST", scope: "fragment", description: "No executable code before INIT_BEGIN or between INIT_END and PARSE_BEGIN." },
  { id: "FRAG-NO-WRAPPER-DECLS", level: "MUST", scope: "fragment", description: "The fragment never declares the platform wrapper (module Fluent, register_parser, StellarInnerParseClass, Parser_customized_*)." },
  { id: "FRAG-INITIALIZE", level: "MUST", scope: "fragment", description: "def initialize is inside the INIT region." },
  { id: "FRAG-RULESET", level: "MUST", scope: "fragment", description: "@parser_rule_set is assigned inside the INIT region (the wrapper reads it through the inner class)." },
  { id: "FRAG-PARSE", level: "MUST", scope: "fragment", description: "def parse(text) is inside the PARSE region." },
  { id: "FRAG-YIELD", level: "MUST", scope: "fragment", description: "parse hands results to the wrapper with yield." },
  { id: "FRAG-ERROR-CONTRACT", level: "MUST", scope: "fragment", description: "The PARSE region sets parser_err_msg on failure records (the wrapper keys off it)." },
  { id: "FRAG-LOG-INDEX", level: "MUST", scope: "fragment", description: "The fragment assigns stellar_log_index (the CONF routes on it)." },
  { id: "FRAG-EMPTY-INPUT", level: "SHOULD", scope: "fragment", description: "Nil or empty input yields nil, nil." },
  { id: "CONF-SYNTAX", level: "MUST", scope: "conf", description: "The CONF has balanced Fluentd sections." },
  { id: "CONF-SOURCE-TYPES", level: "MUST", scope: "conf", description: "Every <source> is udp or tcp and at least one exists." },
  { id: "CONF-BIND", level: "MUST", scope: "conf", description: "Every <source> has bind 0.0.0.0 or 127.0.0.1 and equals the project's bind when one is declared." },
  { id: "CONF-PORT-SHARED", level: "MUST", scope: "conf", description: "All <source> sections of one CONF use the same port." },
  { id: "CONF-TAG", level: "MUST", scope: "conf", description: "Every <source> has tag equal to the parser name." },
  { id: "CONF-PARSE-TYPE", level: "MUST", scope: "conf", description: "Every <source> has <parse> @type <parser name>." },
  { id: "CONF-TCP-INCLUDE", level: "MUST", scope: "conf", description: "Every tcp <source> includes /etc/td-agent/transport_settings.conf." },
  { id: "CONF-MATCH", level: "MUST", scope: "conf", description: "Exactly one <match <parser name>.**> using rewrite_tag_filter." },
  { id: "CONF-CAPITALIZE", level: "MUST", scope: "conf", description: "capitalize_regex_backreference yes is set on the match." },
  { id: "CONF-RULE-KEY", level: "MUST", scope: "conf", description: "Every rewrite rule keys on stellar_log_index." },
  { id: "CONF-RULE-ORDER", level: "MUST", scope: "conf", description: "Class rules come first (first match wins), each matching only its own index, and exactly one inverted syslog guard comes last." },
  { id: "PAIR-PROTOCOLS", level: "MUST", scope: "pair", description: "The CONF source types equal the project's protocols." },
  { id: "PAIR-CLASSIFICATION-ROUTES", level: "MUST", scope: "pair", description: "Every non-syslog class the parser can emit has a CONF route." },
];

const LEVEL = new Map(CONFORMANCE_RULES.map(rule => [rule.id, rule.level] as const));
const finding = (rule: string, message: string): ConformanceFinding => ({ rule, level: LEVEL.get(rule)!, message });

const MARKERS = ["STELLAR_INIT_BEGIN", "STELLAR_INIT_END", "STELLAR_PARSE_BEGIN", "STELLAR_PARSE_END"] as const;
const isBlank = (line: string) => line.trim() === "";
const isCode = (line: string) => !isBlank(line) && !line.trim().startsWith("#");

export function checkFragmentStructure(ruby: string): ConformanceFinding[] {
  const out: ConformanceFinding[] = [];
  const lines = ruby.split("\n");
  const at = MARKERS.map(marker => {
    const re = new RegExp("^\\s*#\\s*" + marker + "\\s*$");
    return lines.reduce<number[]>((acc, line, i) => (re.test(line) ? [...acc, i] : acc), []);
  });
  const unique = at.every(positions => positions.length === 1);
  const first = at.map(positions => positions[0] ?? -1);
  if (!unique || !(first[0]! < first[1]! && first[1]! < first[2]! && first[2]! < first[3]!)) {
    out.push(finding("FRAG-MARKERS", "Expected each of " + MARKERS.join(", ") + " exactly once and in order; found " +
      at.map((p, i) => MARKERS[i] + "x" + p.length).join(" ") + "."));
    return out;
  }
  const [initBegin, initEnd, parseBegin, parseEnd] = first as [number, number, number, number];
  const region = (from: number, to: number) => lines.slice(from + 1, to);
  const code = (from: number, to: number) => region(from, to).filter(isCode);

  if (lines.slice(parseEnd + 1).some(line => !isBlank(line)))
    out.push(finding("FRAG-NO-CODE-AFTER-PARSE-END", "Content follows STELLAR_PARSE_END; installed fragments end at that marker."));
  if (code(-1, initBegin).length || code(initEnd, parseBegin).length)
    out.push(finding("FRAG-REGION-GAP", "Executable code outside the INIT/PARSE regions (before INIT_BEGIN or between INIT_END and PARSE_BEGIN)."));

  const nonComment = lines.filter(line => !line.trim().startsWith("#")).join("\n");
  if (/^\s*module\s+Fluent\b/m.test(nonComment) || /register_parser/.test(nonComment) ||
      /StellarInnerParseClass/.test(nonComment) || /class\s+Parser_customized/.test(nonComment))
    out.push(finding("FRAG-NO-WRAPPER-DECLS", "The fragment declares platform wrapper constructs."));

  const init = region(initBegin, initEnd).join("\n");
  const parse = region(parseBegin, parseEnd).join("\n");
  const body = init + "\n" + parse;
  if (!/^\s*def\s+initialize\b/m.test(init)) out.push(finding("FRAG-INITIALIZE", "def initialize not found in the INIT region."));
  if (!/@parser_rule_set\s*=/.test(init)) out.push(finding("FRAG-RULESET", "@parser_rule_set is not assigned in the INIT region."));
  if (!/^\s*def\s+parse\(\s*text\s*\)/m.test(parse)) out.push(finding("FRAG-PARSE", "def parse(text) not found in the PARSE region."));
  if (!/\byield\b/.test(parse)) out.push(finding("FRAG-YIELD", "parse never yields to the wrapper."));
  if (!/parser_err_msg/.test(parse)) out.push(finding("FRAG-ERROR-CONTRACT", "The PARSE region never sets parser_err_msg."));
  if (!/stellar_log_index/.test(body)) out.push(finding("FRAG-LOG-INDEX", "stellar_log_index is never assigned."));
  if (!/yield\s+nil\s*,\s*nil/.test(parse)) out.push(finding("FRAG-EMPTY-INPUT", "Nil or empty input does not yield nil, nil."));
  return out;
}

export interface ConfNode { name: string; args: string; params: Array<{ key: string; value: string }>; includes: string[]; children: ConfNode[] }

export function parseFluentConf(text: string): { root: ConfNode; errors: string[] } {
  const make = (name: string, args = ""): ConfNode => ({ name, args, params: [], includes: [], children: [] });
  const root = make("root");
  const stack = [root];
  const errors: string[] = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const open = /^<([A-Za-z_]\w*)\s*(.*?)>$/.exec(line);
    const close = /^<\/([A-Za-z_]\w*)>$/.exec(line);
    const top = stack[stack.length - 1]!;
    if (open) { const node = make(open[1]!, open[2]!); top.children.push(node); stack.push(node); return; }
    if (close) {
      if (stack.length === 1 || top.name !== close[1]) errors.push("line " + (i + 1) + ": unexpected </" + close[1] + ">");
      else stack.pop();
      return;
    }
    const include = /^@include\s+(\S+)/.exec(line);
    if (include) { top.includes.push(include[1]!); return; }
    const param = /^(\S+)(?:\s+(.*))?$/.exec(line)!;
    top.params.push({ key: param[1]!, value: (param[2] ?? "").trim() });
  });
  if (stack.length > 1) errors.push("unclosed <" + stack[stack.length - 1]!.name + ">");
  return { root, errors };
}

const param = (node: ConfNode, key: string) => node.params.find(p => p.key === key)?.value;
const CLASS_INDICES = ["threat", "session", "winlogevent"] as const;
const ALL_INDICES = [...CLASS_INDICES, "syslog"] as const;
const TRANSPORT_INCLUDE = "/etc/td-agent/transport_settings.conf";

function regexOf(value: string | undefined): RegExp | undefined {
  const match = /^\/(.*)\/$/.exec(value ?? "");
  if (!match) return undefined;
  try { return new RegExp(match[1]!); } catch { return undefined; }
}

export interface ConfContext { parserName: string; expectedBind?: string }

export function checkConfStructure(conf: string, ctx: ConfContext): ConformanceFinding[] {
  const out: ConformanceFinding[] = [];
  const { root, errors } = parseFluentConf(conf);
  if (errors.length) return [finding("CONF-SYNTAX", errors.join("; "))];
  const sources = root.children.filter(node => node.name === "source");
  if (!sources.length || sources.some(s => !["udp", "tcp"].includes(param(s, "@type") ?? "")))
    out.push(finding("CONF-SOURCE-TYPES", "Expected at least one <source> and only udp/tcp source types."));
  for (const source of sources) {
    const bind = param(source, "bind");
    if (bind !== "0.0.0.0" && bind !== "127.0.0.1")
      out.push(finding("CONF-BIND", "bind must be 0.0.0.0 or 127.0.0.1, found " + String(bind)));
    else if (ctx.expectedBind !== undefined && bind !== ctx.expectedBind)
      out.push(finding("CONF-BIND", "bind " + bind + " differs from the project bind " + ctx.expectedBind));
    if (param(source, "tag") !== ctx.parserName) out.push(finding("CONF-TAG", "tag must equal " + ctx.parserName));
    const parse = source.children.find(child => child.name === "parse");
    if (!parse || param(parse, "@type") !== ctx.parserName) out.push(finding("CONF-PARSE-TYPE", "<parse> @type must equal " + ctx.parserName));
    if (param(source, "@type") === "tcp" && !source.includes.includes(TRANSPORT_INCLUDE))
      out.push(finding("CONF-TCP-INCLUDE", "tcp source must @include " + TRANSPORT_INCLUDE));
  }
  if (new Set(sources.map(s => param(s, "port"))).size > 1 || sources.some(s => !/^\d+$/.test(param(s, "port") ?? "")))
    out.push(finding("CONF-PORT-SHARED", "All sources must share one numeric port."));

  const matches = root.children.filter(node => node.name === "match");
  const match = matches[0];
  if (matches.length !== 1 || match!.args !== ctx.parserName + ".**" || param(match!, "@type") !== "rewrite_tag_filter") {
    out.push(finding("CONF-MATCH", "Expected exactly one <match " + ctx.parserName + ".**> with @type rewrite_tag_filter."));
    return out;
  }
  if (param(match, "capitalize_regex_backreference") !== "yes") out.push(finding("CONF-CAPITALIZE", "capitalize_regex_backreference yes is required."));
  const rules = match.children.filter(node => node.name === "rule");
  if (rules.some(rule => param(rule, "key") !== "stellar_log_index")) out.push(finding("CONF-RULE-KEY", "Every rule must use key stellar_log_index."));

  const problems: string[] = [];
  const inverted = rules.filter(rule => param(rule, "invert") === "true");
  if (!rules.length || inverted.length !== 1 || rules[rules.length - 1] !== inverted[0] || param(inverted[0]!, "tag") !== "syslog")
    problems.push("exactly one inverted syslog guard must be the last rule");
  const classRules = rules.filter(rule => rule !== inverted[0]);
  const tags = classRules.map(rule => param(rule, "tag"));
  if (new Set(tags).size !== tags.length) problems.push("duplicate class tag");
  for (const rule of classRules) {
    const tag = param(rule, "tag") ?? "";
    const pattern = regexOf(param(rule, "pattern"));
    if (!(CLASS_INDICES as readonly string[]).includes(tag) || param(rule, "invert") === "true") { problems.push("class rule tag " + tag + " is not a routable class"); continue; }
    if (!pattern) { problems.push("unreadable pattern for " + tag); continue; }
    if (!pattern.test(tag)) problems.push("pattern for " + tag + " does not match its own index");
    for (const other of ALL_INDICES.filter(index => index !== tag))
      if (pattern.test(other)) problems.push("pattern for " + tag + " also matches " + other);
  }
  const guard = inverted.length === 1 ? regexOf(param(inverted[0]!, "pattern")) : undefined;
  if (inverted.length === 1 && !guard) problems.push("unreadable guard pattern");
  if (guard) {
    if (guard.test("syslog")) problems.push("guard pattern matches syslog, so syslog events would be dropped");
    for (const tag of tags) if (tag && !guard.test(tag)) problems.push("guard pattern does not cover class " + tag);
  }
  if (problems.length) out.push(finding("CONF-RULE-ORDER", problems.join("; ")));
  return out;
}

export interface PairContext extends ConfContext {
  ruby: string;
  conf: string;
  protocols?: readonly string[];
  classificationIndices?: readonly string[];
}

export function checkPairConformance(ctx: PairContext): ConformanceFinding[] {
  const out = [...checkFragmentStructure(ctx.ruby), ...checkConfStructure(ctx.conf, ctx)];
  const { root, errors } = parseFluentConf(ctx.conf);
  if (errors.length) return out;
  if (ctx.protocols) {
    const actual = root.children.filter(n => n.name === "source").map(n => param(n, "@type")).sort().join(",");
    if (actual !== [...ctx.protocols].sort().join(","))
      out.push(finding("PAIR-PROTOCOLS", "CONF sources " + actual + " differ from the project protocols " + [...ctx.protocols].sort().join(",")));
  }
  if (ctx.classificationIndices) {
    const match = root.children.find(n => n.name === "match");
    const routed = new Set((match?.children ?? []).filter(n => n.name === "rule" && param(n, "invert") !== "true").map(n => param(n, "tag")));
    const missing = [...new Set(ctx.classificationIndices)].filter(index => index !== "syslog" && !routed.has(index));
    if (missing.length) out.push(finding("PAIR-CLASSIFICATION-ROUTES", "No CONF route for classes: " + missing.join(", ")));
  }
  return out;
}

export function assertPairConformance(ctx: PairContext): ConformanceFinding[] {
  const findings = checkPairConformance(ctx);
  const musts = findings.filter(f => f.level === "MUST");
  if (musts.length)
    throw new Error("Reference conformance failed for " + ctx.parserName + ": " + musts.map(f => f.rule + " (" + f.message + ")").join("; "));
  return findings;
}
