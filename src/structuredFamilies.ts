import {hasDuplicateJsonObjectKeys} from './jsonDuplicateKeys';
import {hasUnsafeJsonNumbers} from './jsonNumberSafety';
import {jsonSourceValueValid} from './jsonSourceSafety';
import { parseRfc5424Subset } from './rfc5424Subset';
import { isSupportedRfc5424Version, matchHeaderRule, matchesHeaderToken } from './grammar/syslogHeader';
import { matchRfc3164Header } from './grammar/syslogHeader';
import { parseStrictKeyValues } from './grammar/kvBody';
import { GRAMMAR_FRAGMENTS, SYSLOG_HEADER_SEMANTICS, SYSLOG_HEADER_TOKENS } from './grammar/syslogHeaderGrammar.generated';
import {extractPortableRegexFields} from './portableRegexExtraction';
/* Browser-only structural subset of RFC5424, CEF and LEEF.
   Does not execute Ruby or imply native Fluentd target compatibility. */
export type StructuredFamily = 'syslog_rfc3164' | 'syslog_rfc5424' | 'cef' | 'leef';
export interface StructuredExtraction {
  fields: Record<string, unknown>;
  errors: string[];
}
const failure = (message: string): StructuredExtraction => ({ fields: {}, errors: [message] });

// Which body dialect an extraction actually parsed. Kept beside the result instead of inside it so the
// result shape (fields, errors) stays what every consumer and test already expects.
const BODY_KIND = new WeakMap<object, string>();
const withBodyKind = <T extends StructuredExtraction>(extraction: T, kind: string | undefined): T => {
  if (kind !== undefined && extraction.errors.length === 0) BODY_KIND.set(extraction, kind);
  return extraction;
};
/** 'kv', 'json', 'cef', 'leef', 'regex' or 'raw' when the extractor resolved a body dialect for this result (also for `auto`). */
export const bodyKindOf = (extraction: StructuredExtraction): string | undefined => BODY_KIND.get(extraction);

export function detectStructuredFamily(input: string): StructuredFamily | null {
  if (/^CEF:\d+\|/.test(input)) return 'cef';
  if (/^LEEF:(?:1\.0|2\.0)\|/.test(input)) return 'leef';
  // An RFC 5424 shaped header is labelled RFC 5424 only for a VERSION the contract supports.
  const ietf = /^<\d{1,3}>([1-9]\d?) \S+ \S+ \S+ /.exec(input);
  if (ietf && isSupportedRfc5424Version(ietf[1]!)) return 'syslog_rfc5424';
  if (/^<\d{1,3}>[A-Z][a-z]{2} +\d{1,2} +\d{2}:\d{2}:\d{2} /.test(input)) return 'syslog_rfc3164';
  // Bounded BSD security envelope without TAG: timestamp, an optional host
  // and then an explicit structured body. Free-form prose is excluded. The
  // header grammar comes from contracts/syslog-header-grammar.v1.json.
  // Detection is syntax only on the first line, like the PRI check above;
  // calendar and PRI range errors are reported by extraction.
  const first = input.split(/\r?\n/, 1)[0] ?? '';
  const bsd = matchHeaderRule('rfc3164_tagged', first) ? null
    : matchHeaderRule('rfc3164_tagless', first) ?? matchHeaderRule('rfc3164_hostless', first);
  if (bsd && matchesHeaderToken('STRUCTURED_BODY', bsd.message ?? ''))
    return 'syslog_rfc3164';
  return null;
}

function splitEscaped(text: string, delimiter: string, splits: number): string[] | null {
  const output = [''];
  let escaped = false;
  for (const char of text) {
    // Everything after the last header delimiter belongs to the extension grammar and is kept exactly as
    // written. Decoding header escapes there as well decoded a value twice: "C:\\new" became "C:" LF "ew".
    if (output.length > splits) { output[output.length - 1] += char; continue; }
    if (escaped) {
      output[output.length - 1] += char === delimiter || char === '\\' ? char : '\\' + char;
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else if (char === delimiter && output.length <= splits) {
      output.push('');
    } else {
      output[output.length - 1] += char;
    }
  }
  if (escaped) return null;
  return output.length === splits + 1 ? output : null;
}

/**
 * Owner policy D-1: a field that appears more than once is never reduced to one of its values. The event
 * is declined, and the message names the field so the reviewer can see what has to be resolved.
 */
export const duplicateFieldMessage = (key: string): string =>
  'Duplicate field "' + key + '": the same name appears more than once in the event. No value is overwritten, and the event is not parsed automatically.';

export function strictKeyValues(input: string): StructuredExtraction {
  // Pair grammar, separators, limits and escapes come from the shared grammar
  // contract (src/grammar/kvBody.ts); the Ruby export reads the same fragment.
  const body = parseStrictKeyValues(input);
  if (!body.ok) return failure({
    MALFORMED_PAIR: 'Unsupported or malformed extension key=value segment',
    FORBIDDEN_KEY: 'Unsafe field name: ' + String(body.key),
    DUPLICATE_KEY: duplicateFieldMessage(String(body.key)),
    TOO_MANY_PAIRS: 'KV field limit exceeded: maximum 100 keys per event',
    NO_PAIRS: 'No extension fields parsed',
  }[body.reason]);
  const values: Record<string, unknown> = Object.create(null);
  for (const [key, value] of body.pairs) values[key] = value;
  return withBodyKind({ fields: values, errors: [] }, 'kv');
}

// Key token, field limit, escape table, supported versions and forbidden keys come from the shared grammar
// contract; the generated Ruby and the Python preview read the same values.
// CEF and LEEF read their grammar from the shared contract (contracts/syslog-header-grammar.v1.json): the
// generated Ruby and the Python preview compile the same fragments, so the three scanners have one control flow.
const CEF_PAIR=new RegExp(GRAMMAR_FRAGMENTS.cef_pair.source,'y');
const CEF_ESCAPE=new RegExp(SYSLOG_HEADER_TOKENS.CEF_ESCAPE,'g');
const CEF_ESCAPES:Readonly<Record<string,string>>=SYSLOG_HEADER_SEMANTICS.cefExtensionEscapes;
const CEF_VERSIONS:readonly string[]=SYSLOG_HEADER_SEMANTICS.cefSupportedVersions;
const LEEF_VERSIONS:readonly string[]=SYSLOG_HEADER_SEMANTICS.leefSupportedVersions;
const LEEF_DELIMITER_VERSIONS:readonly string[]=SYSLOG_HEADER_SEMANTICS.leefDelimiterFieldVersions;
const LEEF_DELIMITER=new RegExp(GRAMMAR_FRAGMENTS.leef_delimiter.source,'y');
const LEEF_EXTRA_DELIMITERS:readonly number[]=SYSLOG_HEADER_SEMANTICS.leefDelimiterExtraCodePoints;
const LEEF_ATTRIBUTE=new RegExp(GRAMMAR_FRAGMENTS.leef_attribute.source,'y');
const FORBIDDEN_KEYS:readonly string[]=SYSLOG_HEADER_SEMANTICS.kvForbiddenKeys;
/** A backslash pair listed in the contract is decoded; any other pair is kept as written. */
const decodeCefValue=(raw:string):string=>raw.replace(CEF_ESCAPE,pair=>
  Object.prototype.hasOwnProperty.call(CEF_ESCAPES,pair[1]!)?CEF_ESCAPES[pair[1]!]!:pair);
function cefExtensionValues(input:string):StructuredExtraction{
  const values:Record<string,unknown>=Object.create(null);
  let cursor=0,count=0;
  for(;;){
    CEF_PAIR.lastIndex=cursor;
    const match=CEF_PAIR.exec(input);
    if(!match)break;
    if(count++>=SYSLOG_HEADER_SEMANTICS.cefMaxExtensionFields)return failure('CEF extension field limit exceeded');
    const key=match.groups!.key!;
    if(FORBIDDEN_KEYS.includes(key))return failure('Unsupported CEF extension field');
    if(Object.prototype.hasOwnProperty.call(values,key))return failure(duplicateFieldMessage(key));
    values[key]=decodeCefValue(match.groups!.value!);
    cursor=CEF_PAIR.lastIndex;
  }
  // Text the pair grammar does not account for (a broken key boundary, a backslash that escapes nothing).
  if(cursor!==input.length)return failure('Unsupported CEF extension key boundary');
  if(!Object.keys(values).length)return failure('No CEF extension fields parsed');
  return {fields:values,errors:[]};
}

/**
 * The attribute delimiter of a LEEF event: the contract default, or the delimiter field of the versions that
 * carry one, written as the character itself or in hexadecimal (0x or x prefix).
 */
function leefDelimiter(field:string|undefined):string|null{
  if(field===undefined)return SYSLOG_HEADER_SEMANTICS.leefDefaultDelimiter;
  LEEF_DELIMITER.lastIndex=0;
  const match=LEEF_DELIMITER.exec(field);
  if(match?.groups!.literal!==undefined)return match.groups!.literal;
  // Hexadecimal spelling, or one literal character from the contract list outside printable ASCII.
  const code=match?parseInt(match.groups!.hex!,16):([...field].length===1?field.codePointAt(0)!:-1);
  if(LEEF_EXTRA_DELIMITERS.includes(code))return String.fromCharCode(code);
  if(!match||code>126)return null;
  const named=String.fromCharCode(code);
  LEEF_DELIMITER.lastIndex=0;
  const valid=LEEF_DELIMITER.exec(named);
  return valid&&valid.groups!.literal!==undefined?named:null;
}

/** Mirror the reviewed backend's bounded JSON object body shape. */
function boundedJsonObject(text: string): StructuredExtraction {
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return failure('RFC5424 JSON body must be an object');
    }
    // The local browser cannot silently keep the last decoded object member
    // while the compiled Ruby parser correctly rejects that original source.
    if (hasDuplicateJsonObjectKeys(text))
      return failure('Duplicate JSON object key in reviewed Syslog body');
    if (hasUnsafeJsonNumbers(text))
      return failure('Unsafe JSON numeric precision: quote large identifiers as strings');
    if (!jsonSourceValueValid(parsed))
      return failure('RFC5424 JSON body exceeds native nesting depth or contains invalid Unicode');
    return { fields: parsed as Record<string, unknown>, errors: [] };
  } catch {
    return failure('RFC5424 JSON body is not valid JSON');
  }
}

// A beginner may infer the bounded body dialect from the current sample,
// but only a subsequent explicit project format is eligible for compilation.
function deterministicBody(text:string):'raw'|'json'|'kv'|'cef'|'leef'{
 if(/^CEF:/.test(text))return 'cef';
 if(/^LEEF:/.test(text))return 'leef';
 if(text.startsWith('{'))return 'json';
 if(/^[A-Za-z_][A-Za-z0-9_.-]*=/.test(text))return 'kv';
 return 'raw';
}
function regexBody(message:string,pattern:string|undefined):StructuredExtraction{
 return extractPortableRegexFields(message,pattern??'');
}
function parsedBody(message:string,mode:'raw'|'json'|'kv'|'cef'|'leef'|'regex',regexPattern?:string):
 StructuredExtraction{
 if(mode==='raw')return {fields:{message},errors:[]};
 const result=mode==='json'?boundedJsonObject(message):
  mode==='kv'?strictKeyValues(message):
  mode==='regex'?regexBody(message,regexPattern):
  extractStructuredFamily(message,mode);
 return result.errors.length?result:withBodyKind({fields:{body:result.fields},errors:[]},mode);
}
function parseRfc3164Strict(input:string,choice:'raw'|'json'|'kv'|'cef'|'leef'|'regex'|'auto',regexPattern?:string):
 StructuredExtraction{
 // Header grammar, capture names, PRI range and calendar come from
 // contracts/syslog-header-grammar.v1.json (src/grammar/syslogHeader.ts).
 const header=matchRfc3164Header(input);
 if(!header.ok)return failure(header.reason==='NO_MATCH'
  ?'RFC3164 bounded BSD security header required'
  :'RFC3164 PRI or calendar value is invalid');
 const tagged=header.rule==='rfc3164_tagged';
 const fields:Record<string,unknown>={
  ...(header.pri!==undefined?{syslog_pri:header.pri}:{}),
  syslog_timestamp:header.timestamp,syslog_time_policy:'YEAR_AND_ZONE_UNKNOWN',
  ...(header.hostname!==undefined?{syslog_hostname:header.hostname}:{}),
  ...(tagged?{syslog_appname:header.tag,...(header.procid?{syslog_procid:header.procid}:{})}:{}),
 };
 const message=header.message;
 const mode=choice==='auto'?deterministicBody(message):choice;
 if(!tagged&&mode==='raw')
  return failure('Tagless RFC3164 requires an explicit structured security body');
 const body=parsedBody(message,mode,regexPattern);
 return body.errors.length?body:withBodyKind({fields:{...fields,...body.fields},errors:[]},bodyKindOf(body));
}

export function extractStructuredFamily(input: string, format: StructuredFamily, bodyFormat: 'raw' | 'json' | 'kv' | 'cef' | 'leef' | 'regex' | 'auto' = 'raw', regexPattern?:string): StructuredExtraction {
  if (input.includes('\n') || input.includes('\r')) return failure('Only one logical record per physical line is supported for pairing.');
  if (format === 'syslog_rfc3164')return parseRfc3164Strict(input,bodyFormat,regexPattern);
  if (format === 'syslog_rfc5424') {
    const scanned=parseRfc5424Subset(input);
    if (!scanned.ok) return failure(scanned.error);
    const body: Record<string, unknown> = {};
    let bodyKind: string | undefined;
    if (scanned.message) {
      const mode=bodyFormat==='auto'?deterministicBody(scanned.message):bodyFormat;
      bodyKind = mode;
      if (mode === 'raw') body.message = scanned.message;
      else if (['json','kv','cef','leef','regex'].includes(mode)) {
        const nested = mode === 'json'
          ? boundedJsonObject(scanned.message)
          : mode === 'kv'
            ? strictKeyValues(scanned.message)
            : mode === 'regex'
              ? regexBody(scanned.message,regexPattern)
              : extractStructuredFamily(scanned.message, mode as 'cef' | 'leef');
        if (nested.errors.length > 0) return nested;
        body.body = nested.fields;
      } else return failure('Unsupported RFC5424 body dialect');
    }
    return withBodyKind({ fields: { ...scanned.fields, ...body }, errors: [] }, bodyKind);
  }
  if (format === 'cef') {
    // dotAll: a value may hold U+2028/U+2029, which '.' alone excludes in ECMAScript but not in Ruby or Python.
    const match = /^CEF:(\d+)\|(.*)$/s.exec(input);
    if (!match || !CEF_VERSIONS.includes(match[1]!)) return failure('Only standalone CEF version zero events are supported');
    const parts = splitEscaped(match[2], '|', 6);
    if (!parts) return failure('CEF requires six header fields and an extension slot');
    const record: Record<string, unknown> = {
      cef_version: match[1], cef_device_vendor: parts[0],
      cef_device_product: parts[1], cef_device_version: parts[2],
      cef_signature_id: parts[3], cef_name: parts[4], cef_severity: parts[5],
    };
    if (parts[6].trim()) {
      const extension = cefExtensionValues(parts[6]);
      if (extension.errors.length) return extension;
      for (const [key, value] of Object.entries(extension.fields)) {
        if (Object.prototype.hasOwnProperty.call(record, key)) return failure('Extension overrides a reserved CEF header field');
        record[key] = value;
      }
    }
    return { fields: record, errors: [] };
  }
  const match = /^LEEF:([0-9.]+)\|(.*)$/s.exec(input);
  if (!match || !LEEF_VERSIONS.includes(match[1]!)) return failure('Only standalone LEEF 1.0 or 2.0 events are supported');
  const carriesDelimiter = LEEF_DELIMITER_VERSIONS.includes(match[1]!);
  const headerFields = SYSLOG_HEADER_SEMANTICS.leefHeaderFields;
  const parts = splitEscaped(match[2], '|', headerFields + (carriesDelimiter ? 1 : 0));
  if (!parts) return failure('LEEF header or declared delimiter is incomplete');
  const delimiter = leefDelimiter(carriesDelimiter ? parts[headerFields] : undefined);
  if (delimiter === null) return failure('Unsupported LEEF 2.0 data delimiter');
  const record: Record<string, unknown> = Object.assign(Object.create(null), {
    leef_version: match[1], leef_vendor: parts[0], leef_product: parts[1],
    leef_product_version: parts[2], leef_event_id: parts[3],
  });
  if (parts[parts.length - 1]) {
    for (const part of parts[parts.length - 1].split(delimiter)) {
      LEEF_ATTRIBUTE.lastIndex = 0;
      const attribute = LEEF_ATTRIBUTE.exec(part);
      const key = attribute?.groups!.key;
      if (key === undefined || FORBIDDEN_KEYS.includes(key)) return failure('Unsupported LEEF extension token');
      if (Object.prototype.hasOwnProperty.call(record, key)) return failure(duplicateFieldMessage(key));
      record[key] = part.slice(LEEF_ATTRIBUTE.lastIndex);
    }
  }
  return { fields: record, errors: [] };
}
