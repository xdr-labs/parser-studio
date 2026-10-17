import { parseRfc5424Subset } from './rfc5424Subset';
import {inspectSourceCompleteness} from './standardSourceCompletenessGate';
import {jsonSourcePreflightError} from './jsonSourcePreflight';
import {validatePreviewRegexPattern} from './regexSafety';
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
  // Bounded tagless BSD security envelope: timestamp + host followed
  // immediately by an explicit structured body. Free-form prose is excluded.
  if (/^(?:<\d{1,3}>)?[A-Z][a-z]{2} +\d{1,2} +\d{2}:\d{2}:\d{2} +[!-~]{1,255} +(?:\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)/.test(input))
    return 'syslog_rfc3164';
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

export function strictKeyValues(input: string, options?:{allowEmptyUnquoted?:boolean}): StructuredExtraction {
  // Source grammar and raw-byte consumption are authoritative before
  // attempting any decoded value extraction. Unknown producer escapes
  // cannot be inferred from a generic backslash convention.
  const review=inspectSourceCompleteness(input,'kv');
  const unresolved=review.issues.filter(issue=>
    !(options?.allowEmptyUnquoted===true&&issue==='EMPTY_ASSIGNMENT_UNQUALIFIED'));
  if(review.disposition==='ABSTAIN_UNSAFE'||unresolved.length)
    return failure('KV source requires review: '+unresolved.join(', '));
  const values: Record<string, unknown> = Object.create(null);
  const pattern = options?.allowEmptyUnquoted
    ? /[ \t]*([A-Za-z_][A-Za-z0-9_.-]*)=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s"'\\])*))/y
    : /[ \t]*([A-Za-z_][A-Za-z0-9_.-]*)=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s"'\\])+))/y;
  let cursor = 0;
  while (cursor < input.length) {
    if (!input.slice(cursor).trim()) break;
    pattern.lastIndex = cursor;
    const token = pattern.exec(input);
    if (!token || token.index !== cursor) return failure('Unsupported or malformed extension key=value segment');
    if(options?.allowEmptyUnquoted&&pattern.lastIndex<input.length&&
      !/[ \t]/.test(input[pattern.lastIndex]!))
      return failure('Missing field separator after key=value segment');
    const key = token[1];
    if (Object.prototype.hasOwnProperty.call(values, key)) return failure('Duplicate extension field');
    values[key] = (token[2] ?? token[3] ?? token[4] ?? '').replace(/\\(.)/gs, '$1');
    cursor = pattern.lastIndex;
  }
  if (!Object.keys(values).length) return failure('No extension fields parsed');
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
  const error=jsonSourcePreflightError(text);
  if(error)return failure(error);
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
function regexBody(message:string,pattern:string|undefined):StructuredExtraction{
 if(validatePreviewRegexPattern(pattern??'')!==null)return failure('Unsafe or invalid bounded Regex body pattern');
 try{
  const match=new RegExp(pattern!).exec(message);
  if(!match?.groups)return failure('Regex body did not match this event');
  const fields=Object.fromEntries(Object.entries(match.groups).filter(([,value])=>value!==undefined));
  return Object.keys(fields).length?{fields,errors:[]}:failure('Regex body returned no named fields');
 }catch{return failure('Invalid bounded Regex body pattern');}
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
const DAYS:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,
 Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
function parseRfc3164Strict(input:string,choice:'raw'|'json'|'kv'|'cef'|'leef'|'regex'|'auto',regexPattern?:string):
 StructuredExtraction{
 const tagged=/^<(\d{1,3})>([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}):(\d{2}):(\d{2}) +([!-~]{1,255}) +([A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\[(\d{1,8})\])?: +(.+)$/.exec(input);
 const tagless=tagged?null:/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}):(\d{2}):(\d{2}) +([!-~]{1,255}) +(.+)$/.exec(input);
 const match=tagged??tagless;
 if(!match)return failure('RFC3164 bounded BSD security header required');
 const priority=match[1]===undefined?undefined:Number(match[1]);
 const [month,day,hour,minute,second]=[
  match[2]!,Number(match[3]),Number(match[4]),Number(match[5]),Number(match[6])];
 if((priority!==undefined&&priority>191)||!DAYS[month]||day<1||day>DAYS[month]||
   hour>23||minute>59||second>59)
  return failure('RFC3164 PRI or calendar value is invalid');
 const unzoned=month+' '+String(day).padStart(2,' ')+
   ' '+match[4]+':'+match[5]+':'+match[6];
 const fields:Record<string,unknown>={
  ...(priority!==undefined?{syslog_pri:priority}:{}),
  syslog_timestamp:unzoned,syslog_time_policy:'YEAR_AND_ZONE_UNKNOWN',
  syslog_hostname:match[7],
  ...(tagged?{syslog_appname:match[8],...(match[9]?{syslog_procid:match[9]}:{})}:{}),
 };
 const message=tagged?match[10]!:match[8]!;
 const mode=choice==='auto'?deterministicBody(message):choice;
 if(tagless&&mode==='raw')
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
    const match = /^CEF:(\d+)\|(.*)$/.exec(input);
    if (!match || !/^[01]$/.test(match[1]!)) return failure('Only standalone CEF versions 0 and 1 are supported');
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
  const match = /^LEEF:(1\.0|2\.0)\|(.*)$/.exec(input);
  if (!match) return failure('Only standalone LEEF 1.0 or 2.0 events are supported');
  const isV2 = match[1] === '2.0';
  const parts = splitEscaped(match[2], '|', isV2 ? 5 : 4);
  if (!parts) return failure('LEEF header or declared delimiter is incomplete');
  const hex = isV2 ? /^(?:0x|x)([0-9a-fA-F]{1,4})$/.exec(parts[4]!) : null;
  let delimiter='\t';
  if(isV2){
    if(hex){
      const codePoint=parseInt(hex[1]!,16);
      if(codePoint===0||codePoint===10||codePoint===13||
         (codePoint>=0xD800&&codePoint<=0xDFFF)||codePoint>0x10FFFF)
        return failure('Unsupported LEEF 2.0 data delimiter');
      delimiter=String.fromCodePoint(codePoint);
    }else{
      delimiter=parts[4]!;
    }
  }
  const delimiterPoints=Array.from(delimiter);
  if (!(delimiter === '\t' || (
    delimiterPoints.length===1&&delimiterPoints[0]!=='='&&delimiterPoints[0]!=='\\'&&
    !/[\u0000-\u001f\u007f]/.test(delimiterPoints[0]!)
  ))) {
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
          ['__proto__','constructor','prototype'].includes(key) ||
          Object.prototype.hasOwnProperty.call(record, key)) return failure('Unsupported or duplicate LEEF extension token');
      record[key] = part.slice(location + 1);
    }
  }
  return { fields: record, errors: [] };
}
