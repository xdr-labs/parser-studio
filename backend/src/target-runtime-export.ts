/**
 * Shipping host-customized pair export adapter profile. Parser projects remain
 * independent of target versions; only the executable artifact boundary may
 * refuse an unsupported native runtime. Browser-only Regex review is allowed.
 *
 * On the observed Stellar Cyber 7.0 agent (Ruby 2.4.9, Fluentd 1.7.4),
 * Regexp.new(..., timeout:) silently enables IGNORECASE instead of a timeout.
 * Therefore no Regex-dependent pair or ZIP can leave this HTTP export adapter.
 */
export const HOST_CUSTOMIZED_TARGET = Object.freeze({
  profile: "stellar70-observed-ruby24" as const,
  ruby: "2.4.9" as const,
  fluentd: "1.7.4" as const,
  regexPreviewSupported: true as const,
  regexExportSupported: false as const,
  targetImportVerified: false as const,
});

export const TARGET_REGEX_EXPORT_ERROR = "TARGET_RUNTIME_REGEX_UNSUPPORTED" as const;
export const TARGET_REGEX_EXPORT_MESSAGE =
  "This parser uses Regex, but the current Stellar Cyber 7.0 export target uses Ruby 2.4.9 without a bounded Regexp timeout. No deployable Ruby/CONF or ZIP can be generated. Review source fields locally or use an independently supported non-Regex grammar.";

interface ExtractionRecord {
  format?:unknown;
  syslogBodyFormat?:unknown;
}
export function requiresUnavailableTargetRegex(extraction:unknown):boolean {
  if(!extraction||typeof extraction!=="object"||Array.isArray(extraction))return false;
  const value=extraction as ExtractionRecord;
  return value.format==="regex"||
    (["syslog_rfc3164","syslog_rfc5424"].includes(String(value.format))&&
     value.syslogBodyFormat==="regex");
}

/** Reject exact v0.1 known emitted helper, not arbitrary user-supplied prose. */
export function pairIncludesUnavailableTargetRegex(input:unknown):boolean {
  if(!input||typeof input!=="object"||Array.isArray(input))return false;
  const files=(input as {files?:unknown}).files;
  return Array.isArray(files)&&files.some(file=>
    !!file&&typeof file==="object"&&typeof file.content==="string"&&
    file.content.includes("def parserstudio_regex(text, settings)"));
}
