import { assertPairConformance } from "./reference-conformance.js";
import {deflateSync} from 'node:zlib';
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { PairExport, ParserProject, ExportFile } from "./types.js";
import unicodeCaseMap from './unicode-case-map.v1.json' with {type:'json'};
import officialEnrichmentTypes from "./stellar7-enrichment-types.json" with { type: "json" };
import { canonicalJson, validateProject } from "./validate.js";
import { analyzeRuby24RegexCost, RUBY24_REGEX_MAX_INPUT_BYTES } from "./ruby24-regex-cost.js";
import { RUBY_GRAMMAR_PLACEHOLDERS } from "./syslog-header-grammar.generated.js";

/**
 * The Ruby templates carry no hand-written Syslog header grammar. Their
 * __PS_GRAMMAR_*__ placeholders are filled from the code generated out of
 * contracts/syslog-header-grammar.v1.json, the same contract the browser uses.
 */
export function injectHeaderGrammar(fragment: string, placeholders: Readonly<Record<string, string>> = RUBY_GRAMMAR_PLACEHOLDERS): string {
  let out = fragment;
  for (const [placeholder, rubySource] of Object.entries(placeholders)) out = out.split(placeholder).join(rubySource);
  const unresolved = /__PS_GR[A-Za-z0-9_]*__/i.exec(out);
  if (unresolved) throw new Error("Grammar contract placeholder is not generated: " + unresolved[0]);
  return out;
}

const CANONICAL_OPERATORS=readFileSync(new URL('../templates/canonical-operators.rb.tpl',import.meta.url),'utf8');
const INDEX_ORDER = ["threat", "session", "winlogevent", "syslog"] as const;
const RUBY_TEMPLATE = readFileSync(new URL("../templates/ruby-fragment.rb.tpl", import.meta.url), "utf8");
const RUBY_FORWARDER_FAMILY_TEMPLATE = readFileSync(new URL("../templates/ruby-forwarder-family.rb.tpl", import.meta.url), "utf8");
// Only actual CSV projects receive this Ruby 2.4 compatibility helper;
// unrelated JSON/KV parser bytes and approved artifact hashes stay stable.
const CSV_RUBY_COMPAT_HELPER = String.raw`
def parserstudio_csv_strip_field_edges(text, separator)
  chars=text.each_char.to_a
  output=''.dup.force_encoding(text.encoding)
  outside_space=''.dup.force_encoding(text.encoding)
  within_quotes=false
  at_field_start=true
  index=0
  while index<chars.length
    char=chars[index]
    if within_quotes
      output << char
      if char == '"'
        if chars[index+1] == '"'
          index+=1
          output << '"'
        else
          within_quotes=false
        end
      end
    elsif char == separator
      outside_space.clear
      output << char
      at_field_start=true
    elsif char == '"' && at_field_start
      outside_space.clear
      output << char
      within_quotes=true
      at_field_start=false
    elsif char == ' ' || char == "\t"
      outside_space << char unless at_field_start
    else
      output << outside_space << char
      outside_space.clear
      at_field_start=false
    end
    index+=1
  end
  output
end

def parserstudio_csv_parse_line(text, separator, strip_edges)
  if defined?(CSV::DEFAULT_OPTIONS) && CSV::DEFAULT_OPTIONS.key?(:strip)
    CSV.parse_line(text, col_sep: separator, liberal_parsing: false, strip: strip_edges)
  else
    input=strip_edges ? parserstudio_csv_strip_field_edges(text,separator) : text
    CSV.parse_line(input, col_sep: separator, liberal_parsing: false)
  end
end
`;
const PARSE_END_MARKER = "# STELLAR_PARSE_END";
// Installed Stellar Cyber customized fragments (455/455 observed) end at the
// PARSE_END marker. Runtime helpers are therefore inserted before it, never
// appended after it.
function insertBeforeParseEnd(fragment: string, helper: string): string {
  if (fragment.split(PARSE_END_MARKER).length !== 2)
    throw new Error("Fragment must contain exactly one STELLAR_PARSE_END marker");
  return fragment.replace(PARSE_END_MARKER, () => helper.replace(/\n*$/, "\n") + PARSE_END_MARKER);
}
const GENERIC_STRUCTURAL_HELPER = readFileSync(new URL("../templates/generic-structural-helper.rb.tpl", import.meta.url), "utf8");
const REGEX_EXTRACTOR_NEEDLE = "  when 'leef'\n    parserstudio_leef(text)\n  else";
const REGEX_EXTRACTOR_BRANCH = "  when 'leef'\n    parserstudio_leef(text)\n  when 'regex'\n    parserstudio_regex(text, settings)\n  else";
const GENERIC_STRUCTURAL_EXTRACTOR_BRANCH = "  when 'leef'\n    parserstudio_leef(text)\n  when 'generic_structural'\n    parserstudio_generic_structural(text)\n  else";
const GENERIC_STRUCTURAL_NORMALIZE_NEEDLE = "def parserstudio_normalize(original)\n  normalized = {}";
const GENERIC_STRUCTURAL_NORMALIZE_BRANCH = "def parserstudio_normalize(original)\n  normalized = {'parserstudio_source' => original}";
const GENERIC_STRUCTURAL_NORMALIZE_NO_RAW_BRANCH = "def parserstudio_normalize(original)\n  normalized = {'parserstudio_source' => parserstudio_without_source_raw(original)}";
// Only emitted when extraction.omitSourceRaw is true; default artifacts are byte-identical.
const SOURCE_RAW_STRIP_HELPER = String.raw`
# Parser Studio: omit generated full-line copies only from known grammar-owned nodes.
# Manufacturer fields named source_raw inside nested kv/fields are still data.
# Mappings read the original extraction and keep exact source values.
def parserstudio_without_source_raw(value)
  return value unless value.is_a?(Hash)
  generated_roots = %w[generic watchguard_message session_envelope asa juniper watchguard]
  value.each_with_object({}) do |(key, item), out|
    if generated_roots.include?(key) && item.is_a?(Hash)
      out[key] = item.reject { |field, _| field == 'source_raw' }
    else
      out[key] = item
    end
  end
end
`;
const REGEX_RUBY_HELPER = String.raw`
# Parser Studio bounded named-capture Regex helper. This fixed helper is
# emitted only for a Regex project; existing parser artifact bytes stay unchanged.
# These two conventional named date/time fields require lexical plausibility.
# A year or timezone is not inferred and the free-text meaning is unverified.
def parserstudio_valid_month_day_capture?(value)
  return false unless value.is_a?(String)
  match = /\A([0-9]{2})[.-]([0-9]{2})\z/.match(value)
  return false unless match
  month, day = match[1].to_i, match[2].to_i
  days = [0,31,29,31,30,31,30,31,31,30,31,30,31]
  month.between?(1,12) && day.between?(1,days[month])
end

def parserstudio_valid_clock_capture?(value)
  return false unless value.is_a?(String)
  match = /\A([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?\z/.match(value)
  return false unless match
  hour, minute, second = match[1].to_i, match[2].to_i, match[3].to_i
  hour <= 23 && minute <= 59 && second <= 60
end

def parserstudio_regex(text, settings)
  pattern = settings['pattern']
  raise ArgumentError, 'Invalid Regex parser pattern' unless pattern.is_a?(String) &&
    pattern.bytesize.between?(1, 256) && !pattern.match?(/[\x00-\x1f\x7f]/) &&
    pattern.include?('(?<')
  # Regexp.timeout= and Regexp::TimeoutError exist only from Ruby 3.2, and
  # Regexp.new accepts a positional options Hash on Ruby 2.4 that silently
  # treats timeout: as truthy IGNORECASE. Where no timeout exists (Stellar 7.0,
  # Ruby 2.4.9) the pattern runs natively only with a generation-time static
  # backtracking-cost proof; otherwise it fails closed. The proof assumes one
  # short line of input, so that bound is enforced here.
  raise ArgumentError, 'Regex parser input must be a String' unless text.is_a?(String)
  timeout_capable = false
  timeout_capable = true if Regexp.respond_to?(:timeout=) && defined?(Regexp::TimeoutError)
  proven = parserstudio_regex_cost_proven?
  unless timeout_capable || proven
    raise ArgumentError, 'Native Regex unsupported: runtime has no Regexp timeout and the pattern has no static cost proof'
  end
  if proven && (text.bytesize > __PARSERSTUDIO_REGEX_MAX_INPUT_BYTES__ || text.include?("\n"))
    raise ArgumentError, 'Regex parser input exceeds the proven bound'
  end
  begin
    expression = timeout_capable ? Regexp.new(pattern, timeout: 0.05) : Regexp.new(pattern)
  rescue RegexpError, ArgumentError
    raise ArgumentError, 'Invalid Regex parser pattern'
  end
  begin
    match = expression.match(text)
  rescue StandardError => error
    if timeout_capable && error.is_a?(Regexp::TimeoutError)
      raise ArgumentError, 'Regex parser timed out'
    end
    raise ArgumentError, 'Regex parser input rejected'
  end
  raise ArgumentError, 'Regex parser did not match event' unless match
  result = {}
  match.names.each do |name|
    value = match[name]
    result[name] = value unless value.nil?
  end
  raise ArgumentError, 'Regex parser returned no named fields' if result.empty?
  # A deliberately broad model-suggested capture must never turn an impossible
  # date or clock into a valid normalized event. Do not echo untrusted values.
  if result.key?('month_day') && !parserstudio_valid_month_day_capture?(result['month_day'])
    raise ArgumentError, 'Invalid reviewed temporal capture'
  end
  if result.key?('clock') && !parserstudio_valid_clock_capture?(result['clock'])
    raise ArgumentError, 'Invalid reviewed temporal capture'
  end
  result
end

def parserstudio_regex_cost_proven?
  __PARSERSTUDIO_REGEX_COST_PROVEN__
end
`;

function checksum(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function commentValue(value:string|undefined):string{
  return (value??"").replace(/[\r\n\x00-\x1f\x7f]/g," ").trim();
}

function identityComments(project:ParserProject):string[]{
  return [
    "# Vendor: "+commentValue(project.vendor),
    "# Product: "+commentValue(project.product),
    "# Product version: "+commentValue(project.productVersion||"unspecified"),
    "# Parser name: customized_"+project.slug,
  ];
}

function emitSource(project: ParserProject, protocol: "udp" | "tcp"): string {
  const type = "customized_" + project.slug;
  const lines = [
    "<source>", "  @type " + protocol,
    "  port " + project.receiver.port,
    "  bind " + project.receiver.bindAddress,
    "  tag " + type,
  ];
  if (protocol === "tcp") lines.push("  @include /etc/td-agent/transport_settings.conf");
  lines.push("  <parse>", "    @type " + type, "  </parse>");
  if(protocol==="tcp"&&["blank_line_json","blank_line_java"].includes(project.receiver.tcpFraming)){
    // Fluentd Config.parse decodes the fixed double-quoted LF LF escapes.
    // Never concatenate a caller-specified delimiter here.
    lines.push('  delimiter "\\n\\n"');
  }
  if (protocol === "tcp" && project.receiver.tcpFraming === "delimiter") {
    lines.push("  delimiter " + project.receiver.delimiter, "  is_delimiter_part_of_log -1");
  }
  lines.push("  message_length_limit " + project.receiver.messageLengthLimit, "</source>");
  return lines.join("\n");
}

function emitConfiguration(project: ParserProject): string {
  const type = "customized_" + project.slug;
  const lines: string[] = [
    "# Generated by XDR Labs Parser Studio - host-reference artifact, NOT INSTALLED",
    "# Native runtime and target parser upload remain PENDING_EVIDENCE.",
    ...identityComments(project),
  ];
  for (const protocol of project.receiver.protocols) lines.push("", emitSource(project, protocol));
  lines.push("", "<match " + type + ".**>", "  @type rewrite_tag_filter", "  capitalize_regex_backreference yes");
  const categories = new Set([project.classification.defaultIndex, ...project.classification.rules.map(x => x.index)]);
  // Host-customized CONF references route each recognized non-syslog class
  // first and finish with an inverted Syslog safety rule. The four inspected
  // installed customized pairs all have this explicit fallback. In particular,
  // even a parser whose default class is Threat must route its own parser error
  // diagnostic (stellar_log_index=syslog) rather than silently drop the record.
  const recognized=INDEX_ORDER.filter(index=>index!=="syslog"&&categories.has(index));
  for(const index of recognized){
    lines.push("  <rule>", "    key stellar_log_index", "    pattern /^"+index+"$/",
      "    tag "+index, "  </rule>");
  }
  const invertGuard=recognized.length?"(?:"+recognized.join("|")+")":"";
  lines.push("  <rule>","    key stellar_log_index",
    "    pattern /^"+invertGuard+"$/", "    tag syslog", "    invert true", "  </rule>");
  lines.push("</match>", "");
  return lines.join("\n");
}

function emitRubyFragment(project: ParserProject): string {
  const base64 = Buffer.from(canonicalJson(project), "utf8").toString("base64");
  const template=(project.extraction.forwarder||project.normalization.eventProfiles)
    ?RUBY_FORWARDER_FAMILY_TEMPLATE:RUBY_TEMPLATE;
  if (!template.includes("__PARSER_PROJECT_B64__")) throw new Error("Template marker missing");
  let fragment=template.replace("__PARSER_PROJECT_B64__", base64);
  const marker='# __PARSERSTUDIO_CANONICAL_OPERATORS__';
  if(template.split(marker).length!==2)throw new Error('Canonical operator marker missing or duplicated');
  fragment=fragment.replace(marker,CANONICAL_OPERATORS);
  if(!fragment.includes('__PARSERSTUDIO_UNICODE_CASE_B64__'))throw new Error('Unicode contract marker missing');
  fragment=fragment.replace('__PARSERSTUDIO_UNICODE_CASE_B64__',
    deflateSync(Buffer.from(JSON.stringify(unicodeCaseMap),'utf8')).toString('base64'));
  if(!fragment.includes("__STELLAR7_ENRICH_TYPES_JSON__"))
    throw new Error("Official enrichment type marker missing");
  const officialJson=JSON.stringify(officialEnrichmentTypes);
  // The source is a bundled static catalog, never user-controlled data.
  if(/[\\'\r\n]/.test(officialJson))throw new Error("Unsafe official type literal");
  fragment=fragment.replace("__STELLAR7_ENRICH_TYPES_JSON__",officialJson);
  const nativeCsv=project.extraction.format==="csv"||
    (project.extraction.format==="mixed"&&project.extraction.mixedFormats?.includes("csv"));
  if(nativeCsv){
    const csvNeedle='row = CSV.parse_line(text, col_sep: separator, liberal_parsing: false, strip: true)';
    if(fragment.split(csvNeedle).length!==2)
      throw new Error("Native CSV parser template mismatch");
    fragment=fragment.replace(csvNeedle,
      'row = parserstudio_csv_parse_line(text, separator, separator != "\\t")');
    fragment=insertBeforeParseEnd(fragment,CSV_RUBY_COMPAT_HELPER);
  }
  const regexBody=(project.extraction.format==="syslog_rfc3164"||
    project.extraction.format==="syslog_rfc5424")&&
    project.extraction.syslogBodyFormat==="regex";
  if(project.extraction.format==="regex"){
    if(!fragment.includes(REGEX_EXTRACTOR_NEEDLE))throw new Error("Regex template marker missing");
    fragment=fragment.replace(REGEX_EXTRACTOR_NEEDLE,REGEX_EXTRACTOR_BRANCH);
  }else if(project.extraction.format==="generic_structural"){
    if(!fragment.includes(REGEX_EXTRACTOR_NEEDLE))throw new Error("Generic structural template marker missing");
    fragment=fragment.replace(REGEX_EXTRACTOR_NEEDLE,GENERIC_STRUCTURAL_EXTRACTOR_BRANCH);
    if(!fragment.includes(GENERIC_STRUCTURAL_NORMALIZE_NEEDLE))throw new Error("Generic structural normalization marker missing");
    const omitRaw=project.extraction.omitSourceRaw===true;
    fragment=fragment.replace(GENERIC_STRUCTURAL_NORMALIZE_NEEDLE,
      omitRaw?GENERIC_STRUCTURAL_NORMALIZE_NO_RAW_BRANCH:GENERIC_STRUCTURAL_NORMALIZE_BRANCH);
    fragment=insertBeforeParseEnd(fragment,GENERIC_STRUCTURAL_HELPER);
    if(omitRaw)fragment=insertBeforeParseEnd(fragment,SOURCE_RAW_STRIP_HELPER);
  }
  if(project.extraction.format==="regex"||regexBody){
    const proven=typeof project.extraction.pattern==="string"&&
      analyzeRuby24RegexCost(project.extraction.pattern).ok;
    fragment=insertBeforeParseEnd(fragment,REGEX_RUBY_HELPER
      .replace("__PARSERSTUDIO_REGEX_COST_PROVEN__",proven?"true":"false")
      .replace("__PARSERSTUDIO_REGEX_MAX_INPUT_BYTES__",String(RUBY24_REGEX_MAX_INPUT_BYTES)));
  }
  return injectHeaderGrammar(fragment);
}

function exportFile(name: string, content: string): ExportFile {
  return { name, content, sha256: checksum(content), bytes: Buffer.byteLength(content, "utf8") };
}

// Fail-closed Reference Parser Conformance gate: every artifact pair leaving the
// compiler must satisfy the structure contract observed on the reference host
// (contracts/stellar-custom-parser-structure.v1.json). A new generation path
// that violates it cannot produce a file, so it cannot reach a user.
export function assertCompiledPairConformance(project: ParserProject, conf: string, ruby: string): void {
  assertPairConformance({
    parserName: "customized_" + project.slug, ruby, conf,
    expectedBind: project.receiver.bindAddress,
    protocols: project.receiver.protocols,
    classificationIndices: [project.classification.defaultIndex, ...project.classification.rules.map(rule => rule.index)],
  });
}

export function compilePair(input: unknown): PairExport {
  const validation = validateProject(input);
  if (!validation.ok) {
    const codes = validation.issues.map(issue => issue.code + ":" + issue.path).join(", ");
    throw new Error("Invalid parser project: " + codes);
  }
  const project = input as ParserProject;
  const prefix = "customized_" + project.slug;
  const confContent = emitConfiguration(project);
  const rubyContent = emitRubyFragment(project);
  assertCompiledPairConformance(project, confContent, rubyContent);
  const files = [
    exportFile(prefix + ".conf", confContent),
    exportFile(prefix, rubyContent),
  ];
  return {
    contract: "host-customized-pair.v0.1",
    files,
    manifest: {
      status: "DRAFT",
      contract: "host-customized-pair.v0.1",
      schemaRevision: "0.1",
      projectId: project.projectId,
      projectRevision: project.revision,
      fileHashes: Object.fromEntries(files.map(file => [file.name, file.sha256])),
      engineVerified: false,
      targetImportVerified: false,
      warnings: [
        "An extensionless Ruby fragment is not a self-registered Fluentd plugin.",
        "Native Fluentd/Ruby engine tests and Stellar Cyber target import are NOT verified.",
        project.receiver.tcpFraming==="blank_line_json"
          ? "Only explicitly TCP blank-line-framed JSON is supported for multiline input; general multiline and mixed Syslog remain unsupported."
          : project.extraction.format==="mixed"&&project.extraction.mixedFormats?.includes("csv")
          ? "Mixed CSV columns and delimiter require explicit user review. Unrecognized rows are not auto-routed and arbitrary schemas remain unsupported."
          : project.receiver.tcpFraming==="blank_line_java"
          ? "Only explicitly TCP LF LF framed bounded Java exception stack traces are supported; arbitrary Java formats, UDP and unframed multiline remain unsupported."
          : project.extraction.format==="mixed"&&
            project.extraction.mixedFormats?.some(f=>f==="rfc3164_cef"||f==="rfc3164_leef")
          ? "Strict RFC3164 CEF/LEEF mixed requires explicit allowlist; year and timezone remain unknown and all unreviewed bodies and multiline remain unsupported."
          : project.extraction.format==="mixed"&&
            project.extraction.mixedFormats?.some(f=>f==="rfc5424_json"||f==="rfc5424_kv")
          ? "Strict RFC5424-wrapped JSON/KV in mixed parsers requires an explicit allowlist; unreviewed Syslog bodies, CSV and multiline remain unsupported."
          : project.extraction.format==="mixed"&&project.extraction.mixedFormats?.includes("rfc3164_kv")
          ? "Only explicitly allowlisted RFC3164 TAG KV mixed events are supported; header year and timezone remain unknown; other mixed Syslog, CSV and unframed multiline remain unsupported."
          : project.extraction.format==="mixed"&&
            project.extraction.mixedFormats?.some(f=>f==="rfc5424_cef"||f==="rfc5424_leef")
          ? "Only explicitly allowlisted RFC5424-wrapped CEF/LEEF mixed events are supported; RFC3164 mixing, arbitrary Syslog/CSV mixing and unframed multiline remain unsupported."
          : "Supported bounded subset: JSON/KV/CSV, RFC3164/RFC5424 explicit body, CEF/LEEF and allowlisted mixed JSON/KV/CEF/LEEF; mixed Syslog and multiline remain unsupported.",
        ...((project.extraction.format==="regex"||
          project.extraction.syslogBodyFormat==="regex") ? [
          analyzeRuby24RegexCost(project.extraction.pattern??"").ok
            ? "Native Regex on Stellar 7.0 Ruby 2.4.9 (no Regexp timeout) runs only because this pattern passed a generation-time static backtracking-cost classification; the generated parser rejects input over "+RUBY24_REGEX_MAX_INPUT_BYTES+" bytes or with a line break. Target import and indexing remain unverified."
            : "Native Regex requires a runtime with Regexp timeout support (Ruby 3.2+) because this pattern has no static cost proof; on Stellar 7.0 Ruby 2.4.9 it fails closed and MUST NOT be treated as a deployable parser."
        ] : []),
        ...(project.extraction.forwarder ? [
          "Only explicitly declared relay-host Syslog envelopes can be unwrapped; sender identity is not authenticated and arbitrary prefixes/rewritten payloads are not certified."
        ] : []),
        ...(project.normalization.eventProfiles ? [
          "Conditional event-family normalization rejects absent/unknown discriminator values; native runtime execution and real target acceptance are not verified."
        ] : []),
        "No production deployment or live sensor installation has occurred.",
      ],
    },
  };
}
