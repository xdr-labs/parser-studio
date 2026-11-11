import {analyzeRuby24RegexCost,RUBY24_REGEX_REJECTION_TEXT} from "./ruby24-regex-cost.js";

/**
 * Shipping host-customized pair export adapter profile. Parser projects remain
 * independent of target versions; only the executable artifact boundary may
 * refuse an unsupported native runtime. Browser-only Regex review is allowed.
 *
 * On the observed Stellar Cyber 7.0 agent (Ruby 2.4.9, Fluentd 1.7.4) there is
 * no Regexp timeout (Ruby 3.2+ only) and Regexp.new(..., timeout:) silently
 * enables IGNORECASE. A Regex pair may therefore leave this adapter only when
 * its pattern passed the generation-time static backtracking-cost
 * classification in ruby24-regex-cost.ts; every other Regex pair is refused.
 */
export const HOST_CUSTOMIZED_TARGET = Object.freeze({
  profile: "stellar70-observed-ruby24" as const,
  ruby: "2.4.9" as const,
  fluentd: "1.7.4" as const,
  regexPreviewSupported: true as const,
  regexExportSupported: true as const,
  regexExportMode: "ruby24-static-cost-proof" as const,
  targetImportVerified: false as const,
});

export const TARGET_REGEX_EXPORT_ERROR = "TARGET_RUNTIME_REGEX_UNSUPPORTED" as const;
export const TARGET_REGEX_EXPORT_MESSAGE =
  "This Regex cannot be exported for Stellar Cyber 7.0: its Ruby 2.4.9 has no Regexp timeout, so only anchored patterns whose backtracking cost is statically bounded are allowed (no overlapping repeats, no ambiguous alternation, at most two scan loops). Anchor the pattern with ^ and separate adjacent repeats with a literal, or use a non-Regex grammar.";

export function ruby24RegexRefusalDetail(pattern:unknown):string{
  if(typeof pattern!=="string")return TARGET_REGEX_EXPORT_MESSAGE;
  const result=analyzeRuby24RegexCost(pattern);
  return result.ok?"":TARGET_REGEX_EXPORT_MESSAGE+" Reason: "+RUBY24_REGEX_REJECTION_TEXT[result.reason]+".";
}

interface ExtractionRecord {
  format?:unknown;
  syslogBodyFormat?:unknown;
  pattern?:unknown;
}
function usesRegex(value:ExtractionRecord):boolean{
  return value.format==="regex"||
    (["syslog_rfc3164","syslog_rfc5424"].includes(String(value.format))&&
     value.syslogBodyFormat==="regex");
}
/** True when the project uses Regex AND its pattern has no static cost proof. */
export function requiresUnavailableTargetRegex(extraction:unknown):boolean {
  if(!extraction||typeof extraction!=="object"||Array.isArray(extraction))return false;
  const value=extraction as ExtractionRecord;
  if(!usesRegex(value))return false;
  return !(typeof value.pattern==="string"&&analyzeRuby24RegexCost(value.pattern).ok);
}

/**
 * Reject a client-supplied pair that contains the Regex helper unless the
 * embedded reviewed project's pattern re-passes the static classification and
 * the fragment itself declares that proof. The embedded project is decoded,
 * never trusted from the caller's metadata.
 */
export function pairIncludesUnavailableTargetRegex(input:unknown):boolean {
  if(!input||typeof input!=="object"||Array.isArray(input))return false;
  const files=(input as {files?:unknown}).files;
  if(!Array.isArray(files))return false;
  return files.some(file=>{
    if(!file||typeof file!=="object"||typeof file.content!=="string")return false;
    const content:string=file.content;
    if(!content.includes("def parserstudio_regex(text, settings)"))return false;
    if(!/def parserstudio_regex_cost_proven\?\n  true\nend/.test(content))return true;
    const encoded=/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/.exec(content)?.[1];
    if(!encoded)return true;
    try{
      const project=JSON.parse(Buffer.from(encoded,"base64").toString("utf8")) as
        {extraction?:unknown};
      return requiresUnavailableTargetRegex(project.extraction);
    }catch{return true;}
  });
}
