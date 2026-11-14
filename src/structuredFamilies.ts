import {hasDuplicateJsonObjectKeys} from './jsonDuplicateKeys';
import {hasUnsafeJsonNumbers} from './jsonNumberSafety';
import {jsonSourceValueValid} from './jsonSourceSafety';
import { parseRfc5424Subset } from './rfc5424Subset';
import { isSupportedRfc5424Version, matchHeaderRule, matchesHeaderToken } from './grammar/syslogHeader';
import { matchRfc3164Header } from './grammar/syslogHeader';
import { parseStrictKeyValues } from './grammar/kvBody';
import {extractPortableRegexFields} from './portableRegexExtraction';
/* Browser-only structural subset of RFC5424, CEF and LEEF.
   Does not execute Ruby or imply native Fluentd target compatibility. */
export type StructuredFamily = 'syslog_rfc3164' | 'syslog_rfc5424' | 'cef' | 'leef';
export interface StructuredExtraction {
  fields: Record<string, unknown>;
  errors: string[];
}
const failure = (message: string): StructuredExtraction => ({ fields: {}, errors: [message] });

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

export function strictKeyValues(input: string): StructuredExtraction {
  // Pair grammar, separators, limits and escapes come from the shared grammar
  // contract (src/grammar/kvBody.ts); the Ruby export reads the same fragment.
  const body = parseStrictKeyValues(input);
  if (!body.ok) return failure({
    MALFORMED_PAIR: 'Unsupported or malformed extension key=value segment',
    FORBIDDEN_KEY: 'Unsafe or duplicate extension field',
    DUPLICATE_KEY: 'Unsafe or duplicate extension field',
    TOO_MANY_PAIRS: 'KV field limit exceeded: maximum 100 keys per event',
    NO_PAIRS: 'No extension fields parsed',
  }[body.reason]);
  const values: Record<string, unknown> = Object.create(null);
  for (const [key, value] of body.pairs) values[key] = value;
  return { fields: values, errors: [] };
}

const CEF_KEY=/[A-Za-z_][A-Za-z0-9_.-]{0,127}=/y;
function cefExtensionValues(input:string):StructuredExtraction{
  const values:Record<string,unknown>=Object.create(null);
  let cursor=0,count=0;
  while(cursor<input.length){
    while(cursor<input.length&&(input[cursor]===' '||input[cursor]==='\t'))cursor++;
    if(cursor===input.length)break;
    if(count++>=1024)return failure('CEF extension field limit exceeded');
    CEF_KEY.lastIndex=cursor;
    const match=CEF_KEY.exec(input);
    if(!match||match.index!==cursor)return failure('Unsupported CEF extension key boundary');
    const key=match[0].slice(0,-1);
    if(['__proto__','constructor','prototype'].includes(key)||
       Object.prototype.hasOwnProperty.call(values,key))
      return failure('Unsupported or duplicate CEF extension field');
    let pos=CEF_KEY.lastIndex;
    let decoded='';
    let boundary=input.length;
    while(pos<input.length){
      const ch=input[pos]!;
      if(ch==='\\'){
        if(pos+1>=input.length)return failure('Truncated CEF escape');
        const next=input[pos+1]!;
        decoded+=next==='n'?'\n':next==='r'?'\r':
          next==='='?'=':next==='\\'?'\\':'\\'+next;
        pos+=2;continue;
      }
      if(ch===' '||ch==='\t'){
        let runEnd=pos;
        while(runEnd<input.length&&(input[runEnd]===' '||input[runEnd]==='\t'))runEnd++;
        CEF_KEY.lastIndex=runEnd;
        const next=CEF_KEY.exec(input);
        if(next&&next.index===runEnd){
          if(runEnd-pos>1)decoded+=input.slice(pos,runEnd-1);
          boundary=runEnd-1;
          pos=runEnd;
          break;
        }
      }
      decoded+=ch;pos++;
    }
    if(boundary===input.length)decoded=decoded.replace(/[ \t]+$/,'');
    values[key]=decoded;
    cursor=boundary===input.length?input.length:boundary+1;
  }
  if(!Object.keys(values).length)return failure('No CEF extension fields parsed');
  return {fields:values,errors:[]};
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
 return result.errors.length?result:{fields:{body:result.fields},errors:[]};
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
 return body.errors.length?body:{fields:{...fields,...body.fields},errors:[]};
}

export function extractStructuredFamily(input: string, format: StructuredFamily, bodyFormat: 'raw' | 'json' | 'kv' | 'cef' | 'leef' | 'regex' | 'auto' = 'raw', regexPattern?:string): StructuredExtraction {
  if (input.includes('\n') || input.includes('\r')) return failure('Only one logical record per physical line is supported for pairing.');
  if (format === 'syslog_rfc3164')return parseRfc3164Strict(input,bodyFormat,regexPattern);
  if (format === 'syslog_rfc5424') {
    const scanned=parseRfc5424Subset(input);
    if (!scanned.ok) return failure(scanned.error);
    const body: Record<string, unknown> = {};
    if (scanned.message) {
      const mode=bodyFormat==='auto'?deterministicBody(scanned.message):bodyFormat;
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
    return { fields: { ...scanned.fields, ...body }, errors: [] };
  }
  if (format === 'cef') {
    // dotAll: a value may hold U+2028/U+2029, which '.' alone excludes in ECMAScript but not in Ruby or Python.
    const match = /^CEF:(\d+)\|(.*)$/s.exec(input);
    if (!match || match[1] !== '0') return failure('Only standalone CEF version zero events are supported');
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
  const match = /^LEEF:(1\.0|2\.0)\|(.*)$/s.exec(input);
  if (!match) return failure('Only standalone LEEF 1.0 or 2.0 events are supported');
  const isV2 = match[1] === '2.0';
  const parts = splitEscaped(match[2], '|', isV2 ? 5 : 4);
  if (!parts) return failure('LEEF header or declared delimiter is incomplete');
  const hex = isV2 ? /^0x([0-9a-fA-F]{1,2})$/.exec(parts[4]) : null;
  const delimiter = isV2 ? (hex ? String.fromCharCode(parseInt(hex[1], 16)) : parts[4]) : '\t';
  if (!(delimiter === '\t' || (/^[!-~]$/.test(delimiter) && delimiter !== '=' && delimiter !== '\\'))) {
    return failure('Unsupported LEEF 2.0 data delimiter');
  }
  const record: Record<string, unknown> = Object.assign(Object.create(null), {
    leef_version: match[1], leef_vendor: parts[0], leef_product: parts[1],
    leef_product_version: parts[2], leef_event_id: parts[3],
  });
  if (parts[parts.length - 1]) {
    for (const part of parts[parts.length - 1].split(delimiter)) {
      const location = part.indexOf('=');
      const key = part.slice(0, location);
      if (location < 0 || !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key) ||
          ['__proto__','constructor','prototype'].includes(key) ||
          Object.prototype.hasOwnProperty.call(record, key)) return failure('Unsupported or duplicate LEEF extension token');
      record[key] = part.slice(location + 1);
    }
  }
  return { fields: record, errors: [] };
}
