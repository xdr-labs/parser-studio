import { parseRfc5424Subset } from './rfc5424Subset';
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
  if (/^<\d{1,3}>[1-9]\d? \S+ \S+ \S+ /.test(input)) return 'syslog_rfc5424';
  if (/^<\d{1,3}>[A-Z][a-z]{2} +\d{1,2} +\d{2}:\d{2}:\d{2} /.test(input)) return 'syslog_rfc3164';
  return null;
}

function splitEscaped(text: string, delimiter: string, splits: number): string[] | null {
  const output = [''];
  let escaped = false;
  for (const char of text) {
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
  const values: Record<string, unknown> = Object.create(null);
  const pattern = /[ \t]*([A-Za-z_][A-Za-z0-9_.-]*)=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s"'\\])+))/y;
  let cursor = 0;
  while (cursor < input.length) {
    if (!input.slice(cursor).trim()) break;
    pattern.lastIndex = cursor;
    const token = pattern.exec(input);
    if (!token || token.index !== cursor) return failure('Unsupported or malformed extension key=value segment');
    const key = token[1];
    if (Object.prototype.hasOwnProperty.call(values, key)) return failure('Duplicate extension field');
    values[key] = (token[2] ?? token[3] ?? token[4] ?? '').replace(/\\(.)/gs, '$1');
    cursor = pattern.lastIndex;
  }
  if (!Object.keys(values).length) return failure('No extension fields parsed');
  return { fields: values, errors: [] };
}

/** Mirror the reviewed backend's bounded JSON object body shape. */
function boundedJsonObject(text: string): StructuredExtraction {
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return failure('RFC5424 JSON body must be an object');
    }
    function depthOkay(value: unknown, depth: number): boolean {
      if (depth > 8) return false;
      if (Array.isArray(value)) return value.every((v) => depthOkay(v, depth + 1));
      if (value && typeof value === 'object') {
        return Object.values(value).every((v) => depthOkay(v, depth + 1));
      }
      return true;
    }
    if (!depthOkay(parsed, 0)) return failure('RFC5424 JSON body exceeds reviewed nesting depth');
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
function parsedBody(message:string,mode:'raw'|'json'|'kv'|'cef'|'leef'):
 StructuredExtraction{
 if(mode==='raw')return {fields:{message},errors:[]};
 const result=mode==='json'?boundedJsonObject(message):
  mode==='kv'?strictKeyValues(message):
  extractStructuredFamily(message,mode);
 return result.errors.length?result:{fields:{body:result.fields},errors:[]};
}
const DAYS:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,
 Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
function parseRfc3164Strict(input:string,choice:'raw'|'json'|'kv'|'cef'|'leef'|'auto'):
 StructuredExtraction{
 const match=/^<(\d{1,3})>([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}):(\d{2}):(\d{2}) +([!-~]{1,255}) +([A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\[(\d{1,8})\])?: +(.+)$/.exec(input);
 if(!match)return failure('RFC3164 strict PRI, BSD time, hostname and TAG: message required');
 const [priority,month,day,hour,minute,second]=[
  Number(match[1]),match[2]!,Number(match[3]),Number(match[4]),
  Number(match[5]),Number(match[6])];
 if(priority>191||!DAYS[month]||day<1||day>DAYS[month]||
   hour>23||minute>59||second>59)
  return failure('RFC3164 PRI or calendar value is invalid');
 const unzoned=month+' '+String(day).padStart(2,' ')+
   ' '+match[4]+':'+match[5]+':'+match[6];
 const fields:Record<string,unknown>={
  syslog_pri:priority,syslog_timestamp:unzoned,
  syslog_time_policy:'YEAR_AND_ZONE_UNKNOWN',
  syslog_hostname:match[7],syslog_appname:match[8],
  ...(match[9]?{syslog_procid:match[9]}:{}),
 };
 const mode=choice==='auto'?deterministicBody(match[10]!):choice;
 const body=parsedBody(match[10]!,mode);
 return body.errors.length?body:{fields:{...fields,...body.fields},errors:[]};
}

export function extractStructuredFamily(input: string, format: StructuredFamily, bodyFormat: 'raw' | 'json' | 'kv' | 'cef' | 'leef' | 'auto' = 'raw'): StructuredExtraction {
  if (input.includes('\n') || input.includes('\r')) return failure('Only one logical record per physical line is supported for pairing.');
  if (format === 'syslog_rfc3164')return parseRfc3164Strict(input,bodyFormat);
  if (format === 'syslog_rfc5424') {
    const scanned=parseRfc5424Subset(input);
    if (!scanned.ok) return failure(scanned.error);
    const body: Record<string, unknown> = {};
    if (scanned.message) {
      const mode=bodyFormat==='auto'?deterministicBody(scanned.message):bodyFormat;
      if (mode === 'raw') body.message = scanned.message;
      else if (['json','kv','cef','leef'].includes(mode)) {
        const nested = mode === 'json'
          ? boundedJsonObject(scanned.message)
          : mode === 'kv'
            ? strictKeyValues(scanned.message)
            : extractStructuredFamily(scanned.message, mode as 'cef' | 'leef');
        if (nested.errors.length > 0) return nested;
        body.body = nested.fields;
      } else return failure('Unsupported RFC5424 body dialect');
    }
    return { fields: { ...scanned.fields, ...body }, errors: [] };
  }
  if (format === 'cef') {
    const match = /^CEF:(\d+)\|(.*)$/.exec(input);
    if (!match || match[1] !== '0') return failure('Only standalone CEF version zero events are supported');
    const parts = splitEscaped(match[2], '|', 6);
    if (!parts) return failure('CEF requires six header fields and an extension slot');
    const record: Record<string, unknown> = {
      cef_version: match[1], cef_device_vendor: parts[0],
      cef_device_product: parts[1], cef_device_version: parts[2],
      cef_signature_id: parts[3], cef_name: parts[4], cef_severity: parts[5],
    };
    if (parts[6].trim()) {
      const extension = strictKeyValues(parts[6]);
      if (extension.errors.length) return extension;
      for (const [key, value] of Object.entries(extension.fields)) {
        if (Object.prototype.hasOwnProperty.call(record, key)) return failure('Extension overrides a reserved CEF header field');
        record[key] = value;
      }
    }
    return { fields: record, errors: [] };
  }
  const match = /^LEEF:(1\.0|2\.0)\|(.*)$/.exec(input);
  if (!match) return failure('Only standalone LEEF 1.0 or 2.0 events are supported');
  const isV2 = match[1] === '2.0';
  const parts = splitEscaped(match[2], '|', isV2 ? 5 : 4);
  if (!parts) return failure('LEEF header or declared delimiter is incomplete');
  const hex = isV2 ? /^0x([0-9a-fA-F]{1,2})$/.exec(parts[4]) : null;
  const delimiter = isV2 ? (hex ? String.fromCharCode(parseInt(hex[1], 16)) : parts[4]) : '\t';
  if (!(delimiter === '\t' || (/^[!-~]$/.test(delimiter) && delimiter !== '=' && delimiter !== '\\'))) {
    return failure('Unsupported LEEF 2.0 data delimiter');
  }
  const record: Record<string, unknown> = {
    leef_version: match[1], leef_vendor: parts[0], leef_product: parts[1],
    leef_product_version: parts[2], leef_event_id: parts[3],
  };
  if (parts[parts.length - 1]) {
    for (const part of parts[parts.length - 1].split(delimiter)) {
      const location = part.indexOf('=');
      const key = part.slice(0, location);
      if (location < 0 || !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key) ||
          Object.prototype.hasOwnProperty.call(record, key)) return failure('Unsupported or duplicate LEEF extension token');
      record[key] = part.slice(location + 1);
    }
  }
  return { fields: record, errors: [] };
}
