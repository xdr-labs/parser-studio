import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { PairExport, ParserProject, ExportFile } from "./types.js";
import { canonicalJson, validateProject } from "./validate.js";

const INDEX_ORDER = ["threat", "session", "winlogevent", "syslog"] as const;
const RUBY_TEMPLATE = readFileSync(new URL("../templates/ruby-fragment.rb.tpl", import.meta.url), "utf8");
const RUBY_FORWARDER_FAMILY_TEMPLATE = readFileSync(new URL("../templates/ruby-forwarder-family.rb.tpl", import.meta.url), "utf8");
// Ruby CSV 3.2 rejects strip:true with TAB as col_sep. Modify only reviewed
// explicit TAB CSV projects, preserving exact artifact bytes and approved
// template digests for every other parser family.
const CSV_TAB_STRIP_NEEDLE = 'row = CSV.parse_line(text, col_sep: separator, liberal_parsing: false, strip: true)';
const CSV_TAB_STRIP_REPLACEMENT = 'row = CSV.parse_line(text, col_sep: separator, liberal_parsing: false, strip: (separator != "\\t"))';

const GENERIC_STRUCTURAL_HELPER = readFileSync(new URL("../templates/generic-structural-helper.rb.tpl", import.meta.url), "utf8");
const REGEX_EXTRACTOR_NEEDLE = "  when 'leef'\n    parserstudio_leef(text)\n  else";
const REGEX_EXTRACTOR_BRANCH = "  when 'leef'\n    parserstudio_leef(text)\n  when 'regex'\n    parserstudio_regex(text, settings)\n  else";
const GENERIC_STRUCTURAL_EXTRACTOR_BRANCH = "  when 'leef'\n    parserstudio_leef(text)\n  when 'generic_structural'\n    parserstudio_generic_structural(text)\n  else";
const GENERIC_STRUCTURAL_NORMALIZE_NEEDLE = "def parserstudio_normalize(original)\n  normalized = {}";
const GENERIC_STRUCTURAL_NORMALIZE_BRANCH = "def parserstudio_normalize(original)\n  normalized = {'parserstudio_source' => original}";
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
  begin
    expression = Regexp.new(pattern, timeout: 0.05)
  rescue RegexpError, ArgumentError
    raise ArgumentError, 'Invalid Regex parser pattern'
  end
  begin
    match = expression.match(text)
  rescue Regexp::TimeoutError
    raise ArgumentError, 'Regex parser timed out'
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
  const tabCsv=project.extraction.csvDelimiter==="\t"&&
    (project.extraction.format==="csv"||
      (project.extraction.format==="mixed"&&project.extraction.mixedFormats?.includes("csv")));
  if(tabCsv){
    if(fragment.split(CSV_TAB_STRIP_NEEDLE).length!==2)
      throw new Error("Strict TAB CSV parser template mismatch");
    fragment=fragment.replace(CSV_TAB_STRIP_NEEDLE,CSV_TAB_STRIP_REPLACEMENT);
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
    fragment=fragment.replace(GENERIC_STRUCTURAL_NORMALIZE_NEEDLE,GENERIC_STRUCTURAL_NORMALIZE_BRANCH);
    fragment+=GENERIC_STRUCTURAL_HELPER;
  }
  if(project.extraction.format==="regex"||regexBody)fragment+=REGEX_RUBY_HELPER;
  return fragment;
}

function exportFile(name: string, content: string): ExportFile {
  return { name, content, sha256: checksum(content), bytes: Buffer.byteLength(content, "utf8") };
}

export function compilePair(input: unknown): PairExport {
  const validation = validateProject(input);
  if (!validation.ok) {
    const codes = validation.issues.map(issue => issue.code + ":" + issue.path).join(", ");
    throw new Error("Invalid parser project: " + codes);
  }
  const project = input as ParserProject;
  const prefix = "customized_" + project.slug;
  const files = [
    exportFile(prefix + ".conf", emitConfiguration(project)),
    exportFile(prefix, emitRubyFragment(project)),
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
