// Single enumeration of every Compiler variant that changes the generated Ruby
// fragment or CONF. The reference-conformance matrix test, the Ruby 2.4.9
// container gate and (later) the browser E2E corpus all iterate this list, so a
// new generation path is only "supported" once it appears here and passes the
// structure contract. contracts/execution-coverage.v1.json is the coverage
// authority: compiler-variant-matrix.test.ts fails when it names a format,
// template or operator that no variant exercises.
import type { ParserProject } from "../src/types.js";
import { sampleProject } from "./fixture.js";

export interface CompilerVariant { id: string; axis: string; project: ParserProject }

const variants: CompilerVariant[] = [];
function add(axis: string, id: string, edit: (p: ParserProject) => void): void {
  const project = sampleProject();
  edit(project);
  variants.push({ id: axis + ":" + id, axis, project });
}
const columns = ["alpha", "bravo", "charlie"];
const relay = { maxHops: 1 as const, relayHosts: ["relay01"] };

for (const format of ["json", "kv", "cef", "leef"] as const)
  add("format", format, p => { p.extraction = { format }; });

for (const delimiter of [",", ";", "\t"] as const)
  add("csv", "delimiter-" + (delimiter === "\t" ? "tab" : delimiter), p => {
    p.extraction = { format: "csv", csvColumns: columns, csvDelimiter: delimiter };
  });

for (const format of ["syslog_rfc3164", "syslog_rfc5424"] as const)
  for (const body of [undefined, "raw", "json", "kv", "cef", "leef", "regex"] as const)
    add("syslog-body", format + "-" + (body ?? "default"), p => {
      p.extraction = { format, ...(body ? { syslogBodyFormat: body } : {}), ...(body === "regex" ? { pattern: "^(?<action>ALLOW)$" } : {}) };
    });

add("format", "regex", p => { p.extraction = { format: "regex", pattern: "^(?<action>ALLOW)$" }; });
add("format", "java_stacktrace", p => {
  p.extraction = { format: "java_stacktrace" };
  p.receiver.protocols = ["tcp"];
  p.receiver.tcpFraming = "blank_line_java";
});
add("framing", "blank_line_json", p => {
  p.extraction = { format: "json" };
  p.receiver.protocols = ["tcp"];
  p.receiver.tcpFraming = "blank_line_json";
});

add("mixed", "json-kv", p => { p.extraction = { format: "mixed", mixedFormats: ["json", "kv"] }; });
add("mixed", "cef-leef", p => { p.extraction = { format: "mixed", mixedFormats: ["cef", "leef"] }; });
add("mixed", "json-csv", p => {
  p.extraction = { format: "mixed", mixedFormats: ["json", "csv"], csvColumns: columns, csvDelimiter: "," };
});
add("mixed", "rfc5424-cef-leef", p => {
  p.receiver.port = 6900;
  p.extraction = { format: "mixed", mixedFormats: ["rfc5424_cef", "rfc5424_leef"] };
});
add("mixed", "rfc5424-json-kv", p => {
  p.receiver.port = 6900;
  p.extraction = { format: "mixed", mixedFormats: ["rfc5424_json", "rfc5424_kv"] };
});
add("mixed", "rfc3164-kv-json", p => {
  p.receiver.port = 6900;
  p.extraction = { format: "mixed", mixedFormats: ["rfc3164_kv", "json"] };
});

add("generic", "default", p => { p.extraction = { format: "generic_structural" }; });
for (const profile of ["syslog_prefix_kv", "leef2_implicit_tab", "syslog_prefix_kv_leef2_implicit_tab_v1"] as const)
  add("generic", profile, p => { p.extraction = { format: "generic_structural", genericStructuralProfile: profile }; });
add("generic", "omit-source-raw", p => { p.extraction = { format: "generic_structural", omitSourceRaw: true }; });

for (const format of ["json", "kv", "cef", "leef", "syslog_rfc3164", "syslog_rfc5424"] as const)
  add("forwarder", format, p => { p.extraction = { format, forwarder: relay }; });

add("event-profiles", "two-families", p => {
  p.normalization.eventProfiles = { discriminator: "event_type", unknown: "reject", variants: [
    { name: "security", equals: "security", topFields: { "user.name": { normalized_name: "username", data_type: "string" } }, nsFields: {}, vendorFields: {} },
    { name: "other", equals: "other", topFields: { "host.name": { normalized_name: "hostname", data_type: "string" } }, nsFields: {}, vendorFields: {} },
  ] };
});

add("receiver", "udp-only", p => { p.receiver.protocols = ["udp"]; });
add("receiver", "tcp-only", p => { p.receiver.protocols = ["tcp"]; });
add("receiver", "tcp-delimiter", p => { p.receiver.protocols = ["tcp"]; p.receiver.tcpFraming = "delimiter"; p.receiver.delimiter = "|"; });
add("bind", "loopback-override", p => { p.receiver.bindAddress = "127.0.0.1"; });
add("bind", "all-interfaces", p => { p.receiver.bindAddress = "0.0.0.0"; });

add("classification", "syslog-only", p => { p.classification = { defaultIndex: "syslog", rules: [] }; });
add("classification", "all-classes", p => {
  p.classification = { defaultIndex: "syslog", rules: [
    { field: "action", operator: "equals", value: "deny", index: "threat" },
    { field: "srcip", operator: "exists", index: "session" },
    { field: "dstip", operator: "exists", index: "winlogevent" },
  ] };
});
add("classification", "threat-default", p => { p.classification = { defaultIndex: "threat", rules: [] }; });

const operators: Array<[string, NonNullable<ParserProject["enrichment"]>[number]]> = [
  ["set_const", { operator: "set_const", target: "log.constant", value: "fixed" }],
  ["copy", { operator: "copy", source: "action", target: "log.action_copy" }],
  ["lowercase", { operator: "lowercase", source: "action", target: "log.action_lower" }],
  ["uppercase", { operator: "uppercase", source: "action", target: "log.action_upper" }],
  ["split_field", { operator: "split_field", source: "action", delimiter: ":", targets: ["log.action_head", "log.action_tail"] }],
  ["merge_fields", { operator: "merge_fields", sources: ["action", "srcip"], delimiter: ":", target: "log.action_merged" }],
];
for (const [name, step] of operators)
  add("enrichment", name, p => {
    // merge_fields needs two string sources of the same type: create one first.
    p.enrichment = name === "merge_fields"
      ? [{ operator: "set_const", target: "log.constant", value: "fixed" }, { ...step, sources: ["action", "log.constant"] } as typeof step]
      : [step];
  });

export function compilerVariants(): CompilerVariant[] {
  // Fresh projects per call: callers may mutate them.
  return variants.map(variant => ({ ...variant, project: structuredClone(variant.project) }));
}
