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
      issue(issues, "schema", path, `Schema validation: ${error.keyword}`);
    }
    return { ok: false, issues };
  }

  const p = input as unknown as ParserProject;
  if (p.receiver.tcpFraming === "delimiter") {
    if (!p.receiver.protocols.includes("tcp") || !p.receiver.delimiter)
      issue(issues, "framing", "/receiver", "Delimiter framing requires TCP and a nonempty delimiter.");
  } else if (p.receiver.delimiter !== undefined) {
    issue(issues, "framing", "/receiver/delimiter", "Only delimiter framing may specify a delimiter.");
  }

  if (p.unsupportedOpaqueBlocks?.length) {
    issue(issues, "opaque_unsupported", "/unsupportedOpaqueBlocks", "Opaque imported Ruby cannot be safely compiled from the no-code model.");
  }

  const destinations: Array<{ path: string; output: string }> = [];
  const normalizedNames = new Set<string>();
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
        ? `vendor.${mapping.normalized_name}` : mapping.normalized_name;
      const duplicate = destinations.find(entry => conflicts(entry.output, output));
      if (duplicate) issue(issues, "destination_collision", path, `Destination collides with ${duplicate.path}.`);
      destinations.push({path, output});
      if (section !== "vendorFields") normalizedNames.add(mapping.normalized_name);
    }
  }
  if (destinations.length === 0)
    issue(issues, "no_fields", "/normalization", "Map at least one source field before compiling.");
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
