import { Ajv } from "ajv";
import projectSchema from "../schema/parser-project.v0.1.schema.json" with { type: "json" };
import type { ParserProject, ValidationIssue, ValidationResult, FieldMap } from "./types.js";

export const MAX_PROJECT_BYTES = 256 * 1024;
const ajv = new Ajv({ allErrors: true, strict: true });
const validateSchema = ajv.compile(projectSchema);
const RESERVED = new Set(["stellar_log_index", "parser_err_msg", "msg_origin",
  "parserstudio_event_family", "parserstudio_transport"]);
const UNSAFE_PARTS = new Set(["__proto__", "constructor", "prototype"]);

/** Fail closed on quantified groups containing another repetition.
 * Length limits alone do not bound backtracking (for example (a{1,3})+).
 * The browser worker independently imposes a wall-clock deadline.
 */
function hasNestedQuantifiers(pattern:string):boolean {
  const stack:{repeated:boolean}[]=[];
  let characterClass=false;
  for(let i=0;i<pattern.length;i++){
    const char=pattern[i];
    if(char==='\\'){i++;continue;}
    if(char==='['&&!characterClass){characterClass=true;continue;}
    if(char===']'&&characterClass){characterClass=false;continue;}
    if(characterClass)continue;
    if(char==='('){
      stack.push({repeated:false});
      if(pattern.startsWith('(?:',i)){i+=2;continue;}
      if(pattern.startsWith('(?<',i)){
        const end=pattern.indexOf('>',i+3);
        if(end>=0){i=end;continue;}
      }
      continue;
    }
    if(char===')'){
      const frame=stack.pop();
      if(!frame)continue;
      const suffix=pattern.slice(i+1);
      const bound=/^\{(\d{1,8})(?:,(\d{0,8}))?\}/.exec(suffix);
      const repeats=suffix.startsWith('+')||suffix.startsWith('*')||
        Boolean(bound&&(bound[2]===''||Number(bound[2]??bound[1])>1));
      if(frame.repeated&&repeats)return true;
      if(stack.length&&(frame.repeated||repeats))stack[stack.length-1]!.repeated=true;
      continue;
    }
    if(!stack.length)continue;
    if(char==='*'||char==='+'||char==='?'){
      stack[stack.length-1]!.repeated=true;
    }else if(char==='{'){
      const bound=/^\{\d{1,8}(?:,\d{0,8})?\}/.exec(pattern.slice(i));
      if(bound){stack[stack.length-1]!.repeated=true;i+=bound[0].length-1;}
    }
  }
  return false;
}

export function validateBoundedRegexPattern(pattern: unknown): string | null {
  if (typeof pattern !== "string" || !pattern.trim()) return "regex_pattern_required";
  if (pattern.length > 256 || /[\x00-\x1f\x7f]/.test(pattern)) return "regex_pattern_limit";
  if (!pattern.includes("(?<")) return "regex_named_capture_required";
  const unsupported = "regex_unsafe_construct";
  if (/\\[1-9]|\\k<|\(\?<[=!]/.test(pattern)) return unsupported;
  if (/\((?:[^()]|\\.)*[+*?](?:[^()]|\\.)*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern))
    return unsupported;
  if (/\((?:\?:)?[^()]*\|[^()]*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern))
    return unsupported;
  if(hasNestedQuantifiers(pattern))return unsupported;
  if (/([A-Za-z0-9])(?:[*+])\1(?:[*+])/.test(pattern)) return unsupported;
  for (const match of pattern.matchAll(/\{(\d{1,8})(?:,(\d{0,8}))?\}/g)) {
    const low=Number(match[1]);
    const high=match[2]===undefined||match[2]===""?low:Number(match[2]);
    if(low>128||high>128)return unsupported;
  }
  const names=[...pattern.matchAll(/\(\?<([A-Za-z_][A-Za-z0-9_]*)>/g)].map(x=>x[1]!);
  if(!names.length||new Set(names).size!==names.length||names.some(x=>UNSAFE_PARTS.has(x)))
    return "regex_named_capture_invalid";
  try { new RegExp(pattern); } catch { return "regex_syntax_invalid"; }
  return null;
}

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
          ["syslog_rfc3164","syslog_rfc5424","generic_structural"].includes(
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
  if(extraction.genericStructuralProfile!==undefined&&extraction.format!=="generic_structural")
    issue(issues,"generic_structural_profile","/extraction/genericStructuralProfile",
      "A Generic Structural profile requires the Generic Structural extraction format.");
  if(extraction.omitSourceRaw!==undefined&&
      (extraction.omitSourceRaw!==true||extraction.format!=="generic_structural"))
    issue(issues,"omit_source_raw","/extraction/omitSourceRaw",
      "omitSourceRaw may only be true and only with the Generic Structural extraction format.");
  if(extraction.format==="java_stacktrace"&&
      p.receiver.tcpFraming!=="blank_line_java")
    issue(issues,"java_blank_line_transport","/receiver/tcpFraming",
      "Native Java stack traces require TCP and an explicit LF LF event boundary.");
  const mixedCsv=extraction.format==="mixed"&&
    extraction.mixedFormats?.includes("csv");
  if (extraction.format === "csv"||mixedCsv) {
    if(mixedCsv&&(
      !Array.isArray(extraction.csvColumns)||extraction.csvColumns.length<2||
      ![",",";","\t"].includes(extraction.csvDelimiter??"INVALID")))
      issue(issues,"mixed_csv_requires_schema","/extraction",
        "Mixed CSV requires at least two reviewed named columns and an explicitly selected comma, semicolon or TAB delimiter.");
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
  const regexSelected=extraction.format==="regex"||
    (["syslog_rfc3164","syslog_rfc5424"].includes(extraction.format)&&extraction.syslogBodyFormat==="regex");
  if(regexSelected){
    const regexIssue=validateBoundedRegexPattern(extraction.pattern);
    if(regexIssue)issue(issues,regexIssue,"/extraction/pattern",
      "Regex requires one bounded, safe named-capture pattern of at most 256 visible characters.");
  }else if(extraction.pattern!==undefined){
    issue(issues,"format_options","/extraction/pattern",
      "Regex pattern is allowed only with Regex extraction or a reviewed Syslog Regex body.");
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
  const allowedMix=new Set(["json","kv","cef","leef","rfc5424_cef","rfc5424_leef","rfc3164_kv","rfc5424_json","rfc5424_kv","rfc3164_cef","rfc3164_leef","csv"]);
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
        "Choose two to four reviewed families; mixed CSV requires explicit column and delimiter schema.");
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
  if (destinations.length === 0 && !p.normalization.eventProfiles)
    issue(issues, "no_fields", "/normalization", "Map at least one source field before compiling.");
  const eventProfiles = p.normalization.eventProfiles;
  if (eventProfiles) {
    if(eventProfiles.discriminator.split(".").some(part=>UNSAFE_PARTS.has(part)))
      issue(issues,"unsafe_field","/normalization/eventProfiles/discriminator",
        "Unsafe event-family selector source path.");
    const profileNames=new Set<string>(),profileValues=new Set<string>();
    for (const [index,profile] of eventProfiles.variants.entries()) {
      const prefix="/normalization/eventProfiles/variants/"+index;
      if(profileNames.has(profile.name)||profileValues.has(profile.equals))
        issue(issues,"duplicate_event_family",prefix,"Duplicate event family or discriminator.");
      profileNames.add(profile.name);profileValues.add(profile.equals);
      const localDestinations=[...destinations];
      for(const section of ["topFields","nsFields","vendorFields"] as const) {
        for(const [source, mapping] of Object.entries(profile[section])) {
          const path=prefix+"/"+section+"/"+source;
          if(source.split(".").some(part=>UNSAFE_PARTS.has(part)) ||
             mapping.normalized_name.split(".").some(part=>UNSAFE_PARTS.has(part)))
            issue(issues,"unsafe_field",path,"Unsafe event-profile field path.");
          if(RESERVED.has(mapping.normalized_name.split(".")[0]!))
            issue(issues,"reserved_field",path,"Event-profile destination is system-managed.");
          if(mapping.data_type==="date" && mapping.time_format!=="iso8601")
            issue(issues,"date_format",path,"Date requires ISO8601.");
          if(mapping.data_type!=="date" && (mapping.time_format || mapping.timezone))
            issue(issues,"date_format",path,"Only dates may declare timezone.");
          const output=section==="vendorFields"?
            p.vendor+"."+mapping.normalized_name:mapping.normalized_name;
          const other=localDestinations.find(d=>conflicts(d.output,output));
          if(other)issue(issues,"destination_collision",path,
            "Event-profile destination collides with "+other.path+".");
          localDestinations.push({path,output});
        }
      }
    }
  }
  if(p.extraction.forwarder){
    // Do not allow generic-structural/regex modes to silently reinterpret
    // wrapped bytes under an unsupported source semantics contract.
    if(!["json","kv","cef","leef","mixed","syslog_rfc3164","syslog_rfc5424"].includes(p.extraction.format))
      issue(issues,"forwarder_format","/extraction/forwarder",
        "Forwarder unwrapping requires an explicitly supported source grammar.");
  }
  for (const [index, entry] of (p.enrichment ?? []).entries()) {
    const path = `/enrichment/${index}`;
    const safeDelimiter = (value: string) => value.length >= 1 && value.length <= 8 && !/[\x00-\x1f\x7f]/.test(value);
    const addTarget = (target: string, type: string) => {
      for (const segment of target.split(".")) {
        if (UNSAFE_PARTS.has(segment))
          issue(issues, "unsafe_field", path, "Prototype/constructor destination segments are forbidden.");
      }
      if (RESERVED.has(target.split(".")[0]!))
        issue(issues, "reserved_field", path, "System-managed output field is reserved.");
      const duplicate = destinations.find(candidate => conflicts(candidate.output, target));
      if (duplicate) issue(issues, "destination_collision", path, `Enrichment target collides with ${duplicate.path}.`);
      destinations.push({path, output: target});
      normalizedNames.add(target);
      normalizedTypes.set(target, type);
    };
    if (entry.operator === "split_field") {
      if (!normalizedNames.has(entry.source))
        issue(issues, "unmapped_enrichment_source", path, "Split source must already exist in the normalized output.");
      if (normalizedTypes.has(entry.source) && normalizedTypes.get(entry.source) !== "string")
        issue(issues, "enrichment_type", path, "Split source must be a string field.");
      if (!safeDelimiter(entry.delimiter))
        issue(issues, "enrichment_delimiter", path, "Split delimiter must be 1-8 visible characters.");
      if (entry.targets.length < 2 || entry.targets.length > 8 || new Set(entry.targets).size !== entry.targets.length)
        issue(issues, "enrichment_targets", path, "Split requires 2-8 unique output targets.");
      for (const target of entry.targets) addTarget(target, "string");
      continue;
    }
    if (entry.operator === "merge_fields") {
      if (entry.sources.length < 2 || entry.sources.length > 8 || new Set(entry.sources).size !== entry.sources.length)
        issue(issues, "enrichment_sources", path, "Merge requires 2-8 unique source fields.");
      for (const source of entry.sources) {
        if (!normalizedNames.has(source))
          issue(issues, "unmapped_enrichment_source", path, "Every merge source must already exist in the normalized output.");
        if (normalizedTypes.has(source) && normalizedTypes.get(source) !== "string")
          issue(issues, "enrichment_type", path, "Merge sources must be string fields.");
      }
      if (!safeDelimiter(entry.delimiter))
        issue(issues, "enrichment_delimiter", path, "Merge delimiter must be 1-8 visible characters.");
      addTarget(entry.target, "string");
      continue;
    }
    if (entry.operator !== "set_const" && !normalizedNames.has(entry.source))
      issue(issues, "unmapped_enrichment_source", path, "Enrichment source must already exist in the normalized output.");
    if ((entry.operator === "lowercase" || entry.operator === "uppercase") &&
        normalizedTypes.has(entry.source) && normalizedTypes.get(entry.source) !== "string")
      issue(issues, "enrichment_type", path, "Text case transforms require a string source field.");
    addTarget(entry.target, entry.operator === "set_const" ? typeof entry.value : (normalizedTypes.get(entry.source) ?? "unknown"));
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
