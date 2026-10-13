import { Ajv } from "ajv";
import projectSchema from "../schema/parser-project.v0.1.schema.json" with { type: "json" };
import type { ParserProject, ValidationIssue, ValidationResult, FieldMap } from "./types.js";

export const MAX_PROJECT_BYTES = 256 * 1024;
const ajv = new Ajv({ allErrors: true, strict: true });
const validateSchema = ajv.compile(projectSchema);
const RESERVED = new Set(["stellar_log_index", "parser_err_msg", "msg_origin"]);
const UNSAFE_PARTS = new Set(["__proto__", "constructor", "prototype"]);

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (value !== null && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(key =>
      JSON.stringify(key) + ":" + canonicalJson((value as Record<string, unknown>)[key])
    ).join(",") + "}";
  }
  return JSON.stringify(value);
}

function issue(issues: ValidationIssue[], code: string, path: string, message: string): void {
  issues.push({ code, path, message });
}

function conflicts(a: string, b: string): boolean {
  return a === b || a.startsWith(b + ".") || b.startsWith(a + ".");
}

export function validateProject(input: unknown): ValidationResult {
  const issues: ValidationIssue[] = [];
  let jsonBytes: number;
  try {
    jsonBytes = Buffer.byteLength(JSON.stringify(input), "utf8");
  } catch {
    return { ok: false, issues: [{ code: "invalid_input", path: "", message: "Project must be a finite JSON value." }] };
  }
  if (jsonBytes > MAX_PROJECT_BYTES) {
    issue(issues, "size_limit", "", "Project JSON exceeds the 256 KiB limit.");
    return { ok: false, issues };
  }
  if (!validateSchema(input)) {
    for (const error of validateSchema.errors ?? []) {
      const path = error.instancePath || (error.params as { additionalProperty?: string }).additionalProperty || "/";
      if (error.keyword === "minimum" && error.instancePath === "/receiver/port" &&
          ["syslog_rfc3164","syslog_rfc5424"].includes(
            (input as ParserProject | null)?.extraction?.format ?? "") &&
          (error.params as { limit?: number }).limit === 6800) {
        issue(issues, "syslog_port_minimum", "/receiver/port",
          "Syslog parser listener port must be at least 6800.");
        continue;
      }
      issue(issues, "schema", path, `Schema validation: ${error.keyword}`);
    }
    return { ok: false, issues };
  }

  const p = input as unknown as ParserProject;
  if(p.receiver.tcpFraming==="blank_line_json"||
     p.receiver.tcpFraming==="blank_line_java"){
    // No auto-reassembly: sender MUST delimit each complete event with LF LF,
    // and the selected bounded body parser MUST match that framing exactly.
    const expected=p.receiver.tcpFraming==="blank_line_java"?"java_stacktrace":"json";
    if(p.extraction.format!==expected||
       p.receiver.protocols.length!==1||
       p.receiver.protocols[0]!=="tcp"||
       p.receiver.delimiter!==undefined)
      issue(issues,expected==="java_stacktrace"?
        "java_blank_line_transport":"json_blank_line_transport","/receiver/tcpFraming",
        "Explicit TCP-only blank-line framing requires the corresponding Java or JSON parser, with no custom delimiter.");
  }else if (p.receiver.tcpFraming === "delimiter") {
    if (!p.receiver.protocols.includes("tcp") || !p.receiver.delimiter)
      issue(issues, "framing", "/receiver", "Delimiter framing requires TCP and a nonempty delimiter.");
  } else if (p.receiver.delimiter !== undefined) {
    issue(issues, "framing", "/receiver/delimiter", "Only delimiter framing may specify a delimiter.");
  }

  const extraction = p.extraction;
  if(extraction.format==="java_stacktrace"&&
      p.receiver.tcpFraming!=="blank_line_java")
    issue(issues,"java_blank_line_transport","/receiver/tcpFraming",
      "Native Java stack traces require TCP and an explicit LF LF event boundary.");
  if (extraction.format === "csv") {
    if (!extraction.csvColumns?.length) {
      issue(issues, "csv_columns", "/extraction/csvColumns", "CSV requires an explicit field name for each column.");
    } else {
      for (const [index, column] of extraction.csvColumns.entries()) {
        if (UNSAFE_PARTS.has(column)) {
          issue(issues, "unsafe_field", `/extraction/csvColumns/${index}`, "Unsafe CSV column name.");
        }
      }
    }
  } else if (extraction.csvColumns !== undefined || extraction.csvDelimiter !== undefined) {
    issue(issues, "format_options", "/extraction", "CSV options are allowed only with CSV format.");
  }
  if (!["syslog_rfc3164","syslog_rfc5424"].includes(extraction.format) && extraction.syslogBodyFormat !== undefined) {
    issue(issues, "format_options", "/extraction/syslogBodyFormat", "Syslog body format is only supported for RFC3164/RFC5424.");
  }

  // RFC3164 omits the year and timezone. A date cast or generated event
  // timestamp would silently invent a value, so forbid it at authoring time.
  if(extraction.format==="syslog_rfc3164"||
     (extraction.format==="mixed"&&extraction.mixedFormats?.some(f=>f==="rfc3164_kv"||f==="rfc3164_cef"||f==="rfc3164_leef"))){
    for(const section of ["topFields","nsFields","vendorFields"] as const){
      const timeField=p.normalization[section]["syslog_timestamp"];
      if(timeField?.data_type==="date"){
        issue(issues,"rfc3164_unzoned_timestamp",
          `/normalization/${section}/syslog_timestamp`,
          "RFC3164 timestamp has no year or timezone; map it only as text.");
      }
    }
  }
  const allowedMix=new Set(["json","kv","cef","leef","rfc5424_cef","rfc5424_leef","rfc3164_kv","rfc5424_json","rfc5424_kv","rfc3164_cef","rfc3164_leef"]);
  if(extraction.format==="mixed"){
    if(extraction.mixedFormats?.some(f=>f==="rfc5424_cef"||f==="rfc5424_leef"||f==="rfc3164_kv"||f==="rfc5424_json"||f==="rfc5424_kv"||f==="rfc3164_cef"||f==="rfc3164_leef")&&
       p.receiver.port<6800)
      issue(issues,"syslog_port_minimum","/receiver/port",
       "Mixed Syslog listener and .conf port must be at least 6800.");
    if(!Array.isArray(extraction.mixedFormats)||
       extraction.mixedFormats.length<2||extraction.mixedFormats.length>4||
       new Set(extraction.mixedFormats).size!==extraction.mixedFormats.length||
       !extraction.mixedFormats.every(format=>allowedMix.has(format)))
      issue(issues,"mixed_family_allowlist","/extraction/mixedFormats",
        "Choose two to four distinct reviewed single-line families; RFC3164 KV/CEF/LEEF and RFC5424 JSON/KV/CEF/LEEF require explicit allowlists.");
  }else if(extraction.mixedFormats!==undefined){
    issue(issues,"format_options","/extraction/mixedFormats",
      "A family allowlist is valid only in strict mixed extraction.");
  }

  if (p.unsupportedOpaqueBlocks?.length) {
    issue(issues, "opaque_unsupported", "/unsupportedOpaqueBlocks", "Opaque imported Ruby cannot be safely compiled from the no-code model.");
  }

  const destinations: Array<{ path: string; output: string }> = [];
  const normalizedNames = new Set<string>();
  const normalizedTypes = new Map<string, string>();
  const namespaces: Array<keyof ParserProject["normalization"]> = ["topFields", "nsFields", "vendorFields"];
  for (const section of namespaces) {
    const mappings = p.normalization[section] as FieldMap;
    for (const [source, mapping] of Object.entries(mappings)) {
      const path = `/normalization/${section}/${source}`;
      for (const part of source.split(".")) if (UNSAFE_PARTS.has(part))
        issue(issues, "unsafe_field", path, "Prototype/constructor field segments are forbidden.");
      for (const part of mapping.normalized_name.split(".")) if (UNSAFE_PARTS.has(part))
        issue(issues, "unsafe_field", path, "Prototype/constructor destination segments are forbidden.");
      if (RESERVED.has(mapping.normalized_name.split(".")[0]!))
        issue(issues, "reserved_field", path, "System-managed output fields are reserved.");
      if (mapping.data_type === "date" && mapping.time_format !== "iso8601")
        issue(issues, "date_format", path, "Date fields require the supported iso8601 format.");
      if (mapping.data_type !== "date" && (mapping.time_format || mapping.timezone))
        issue(issues, "date_format", path, "Time policies are only applicable to date fields.");

      const output = section === "vendorFields"
        ? `${p.vendor}.${mapping.normalized_name}` : mapping.normalized_name;
      const duplicate = destinations.find(entry => conflicts(entry.output, output));
      if (duplicate) issue(issues, "destination_collision", path, `Destination collides with ${duplicate.path}.`);
      destinations.push({path, output});
      normalizedNames.add(output);
      normalizedTypes.set(output, mapping.data_type);
    }
  }
  if (destinations.length === 0)
    issue(issues, "no_fields", "/normalization", "Map at least one source field before compiling.");
  for (const [index, entry] of (p.enrichment ?? []).entries()) {
    const path = `/enrichment/${index}`;
    if (entry.operator !== "set_const" && !normalizedNames.has(entry.source)) {
      issue(issues, "unmapped_enrichment_source", path, "Enrichment source must already exist in the normalized output.");
    }
    if ((entry.operator === "lowercase" || entry.operator === "uppercase") &&
        normalizedTypes.has(entry.source) && normalizedTypes.get(entry.source) !== "string") {
      issue(issues, "enrichment_type", path, "Text case transforms require a string source field.");
    }
    for (const segment of entry.target.split(".")) {
      if (UNSAFE_PARTS.has(segment)) {
        issue(issues, "unsafe_field", path, "Prototype/constructor destination segments are forbidden.");
      }
    }
    if (RESERVED.has(entry.target.split(".")[0]!)) {
      issue(issues, "reserved_field", path, "System-managed output field is reserved.");
    }
    const duplicate = destinations.find(candidate => conflicts(candidate.output, entry.target));
    if (duplicate) {
      issue(issues, "destination_collision", path, `Enrichment target collides with ${duplicate.path}.`);
    }
    destinations.push({path, output: entry.target});
    normalizedNames.add(entry.target);
    normalizedTypes.set(entry.target, entry.operator === "set_const" ? typeof entry.value : (normalizedTypes.get(entry.source) ?? "unknown"));
  }

  for (const rule of p.classification.rules) {
    const path = "/classification/rules";
    if (!normalizedNames.has(rule.field))
      issue(issues, "unmapped_classification_field", path, "Classification must reference an extracted normalized field.");
    if (rule.operator === "equals" && rule.value === undefined)
      issue(issues, "classification_value", path, "Equals requires a value.");
    if (rule.operator === "exists" && rule.value !== undefined)
      issue(issues, "classification_value", path, "Exists cannot have a value.");
    for (const part of rule.field.split(".")) if (UNSAFE_PARTS.has(part))
      issue(issues, "unsafe_field", path, "Unsafe classification field.");
  }
  const seen = new Set<string>();
  for (const [i, rule] of p.classification.rules.entries()) {
    const signature = canonicalJson([rule.field, rule.operator, rule.value ?? null]);
    if (seen.has(signature))
      issue(issues, "duplicate_classification", `/classification/rules/${i}`, "Duplicate ordered classification predicate.");
    seen.add(signature);
  }

  // Validate no overlapping keys that would overwrite system-populated metadata.
  for (const {path, output} of destinations) {
    for (const protectedPath of ["stellar_log_index", "parser_err_msg", "msg_origin"]) {
      if (conflicts(output, protectedPath))
        issue(issues, "reserved_field", path, "Reserved output field would be overwritten.");
    }
  }
  return { ok: issues.length === 0, issues };
}
