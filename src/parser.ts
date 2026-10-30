import {meetsStellar7ValueConstraints} from './stellar7ValueConstraints';
import type { ConcreteFormat, Detection, Diagnostic, EventResult, FieldType, Format, ParserDraft, SuiteResult, TraceStep } from './model';
import { detectStructuredFamily, extractStructuredFamily,strictKeyValues } from './structuredFamilies';
import { lookupFieldValue } from './fieldPaths';
import {parseJavaStacktrace} from './javaStacktrace';
import { validatePreviewRegexPattern } from './regexSafety';
import {validateConventionalTemporalCaptures} from './regexTemporalClaims';
import {extractGenericStructural} from './genericStructural';
import type { EventBoundary } from './guided/contract';
import {inspectDeclaredForwarders} from './guided/declaredForwarder';
import {inspectEventProfile} from './guided/multiEventRouting';
import {hasDuplicateJsonObjectKeys} from './jsonDuplicateKeys';

export const MAX_DATASET_BYTES = 64 * 1024;
export const MAX_EVENTS = 500;
// Security products such as EDR/XDR can emit valid single-line JSON records well above 4 KiB.
// The dataset is already hard-bounded to 64 KiB, so do not reject one valid record earlier.
export const MAX_LINE_CHARS = MAX_DATASET_BYTES;
const VALID_TARGET = /^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*$/;
const UNSAFE_OUTPUT_SEGMENTS=new Set(['__proto__','constructor','prototype']);

function ownSet(record:Record<string,unknown>,key:string,value:unknown):void{
  Object.defineProperty(record,key,{value,writable:true,enumerable:true,configurable:true});
}
function assignNormalizedPath(record:Record<string,unknown>,path:string,value:unknown):boolean{
  if(!VALID_TARGET.test(path))return false;
  const parts=path.split('.');
  if(parts.some(part=>UNSAFE_OUTPUT_SEGMENTS.has(part)))return false;
  let current=record;
  for(let i=0;i<parts.length-1;i++){
    const part=parts[i]!;
    const existing=Object.prototype.hasOwnProperty.call(current,part)?current[part]:undefined;
    if(existing!==undefined&&(!existing||typeof existing!=='object'||Array.isArray(existing)))return false;
    if(existing===undefined){
      const next:Record<string,unknown>={};
      ownSet(current,part,next);current=next;
    }else current=existing as Record<string,unknown>;
  }
  ownSet(current,parts.at(-1)!,value);
  return true;
}
function normalizedPathExists(record:Record<string,unknown>,path:string):boolean{
  return lookupFieldValue(record,path).found;
}

export function detectFormat(raw: string): Detection {
  const value = raw.trim();
  if(parseJavaStacktrace(raw).errors.length===0)return {
    format:'java_stacktrace',confidence:0.96,
    reason:'Bounded Java exception and stack frames (requires verified LF LF framing)'
  };
  const structured = detectStructuredFamily(value);
  if (structured) return { format: structured, confidence: 0.96, reason: 'Recognized standalone structured log header' };
  if (/^[{[]/.test(value)) return { format: 'json', confidence: 0.96, reason: 'Starts with JSON object or array syntax' };
  // Cisco ASA/FTD messages contain commas and key=value fragments inside the
  // free-form message body. Browser-only CSV/KV heuristics must not reinterpret
  // those incidental tokens; the authoritative Funnel source engine owns this family.
  if (/%(?:ASA(?:-session)?|FTD)-\d-\d+:\s/.test(value)) {
    return { format: 'unknown', confidence: 0,
      reason: 'Cisco ASA/FTD message requires the local Multi-Pass source engine' };
  }
  // Plain BSD repeated-message syslog can contain comma-separated prose that
  // looks like CSV. Keep this well-known syslog idiom out of browser CSV/KV
  // heuristics and let the authoritative Multi-Pass engine decide its structure.
  if (/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+.*\bmessage repeated(?:\s+\[\d+\])?:/.test(value)) {
    return { format: 'unknown', confidence: 0,
      reason: 'BSD repeated-message text requires the local Multi-Pass source engine' };
  }
  if (/^<\d{1,3}>(?:\d\s|[A-Z][a-z]{2}\s|\d{4}-)/.test(value)) {
    return { format: 'syslog', confidence: 0.87, reason: 'Syslog priority and header detected' };
  }
  if (/(?:^|\s)[A-Za-z_][\w.-]*=("[^"]*"|'[^']*'|[^\s]+)/.test(value)) {
    return { format: 'kv', confidence: 0.91, reason: 'Key=value tokens detected' };
  }
  if ([',',';','\t'].some(delimiter=>{
    const values=tokenizeCSV(value,delimiter);
    return values!==null&&values.length>=3;
  })) {
    return { format: 'csv', confidence: 0.64,
      reason: 'Delimited values detected; CSV column names require user review' };
  }
  return { format: 'unknown', confidence: 0, reason: 'No supported format signature' };
}

export interface Extraction {
  fields: Record<string, unknown>;
  errors: string[];
}

function extractJSON(raw: string): Extraction {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      return { fields: {}, errors: ['JSON event must be an object'] };
    }
    if(hasDuplicateJsonObjectKeys(raw))
      return {fields:{},errors:['Duplicate JSON object key: review the source before generating a parser']};
    return { fields: parsed as Record<string, unknown>, errors: [] };
  } catch {
    return { fields: {}, errors: ['Invalid JSON object'] };
  }
}

function extractKV(raw: string): Extraction {
  const fields: Record<string, unknown> = {};
  const errors: string[] = [];
  const pattern = /(?:^|\s)([A-Za-z_][\w.-]*)=(?:"((?:\\.|[^"\\])*)"|'([^']*)'|([^\s]+))/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(raw)) !== null) {
    const key = match[1];
    if (Object.prototype.hasOwnProperty.call(fields, key)) {
      errors.push('Duplicate key: ' + key);
      continue;
    }
    fields[key] = match[2] !== undefined ? match[2].replace(/\\"/g, '"') : match[3] ?? match[4];
  }
  if (!Object.keys(fields).length) errors.push('No key=value fields matched');
  return { fields, errors };
}

export function tokenizeCSV(raw: string, delimiter: string): string[] | null {
  // The backend compiles Ruby CSV.parse_line with liberal_parsing: false.
  // This browser subset is intentionally conservative; malformed quoted
  // cells never become successful evidence for native generation.
  if (![',', ';', '\t'].includes(delimiter)) return null;
  const out: string[] = [];
  let token = '';
  let state: 'start' | 'plain' | 'quoted' | 'afterQuote' = 'start';
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (state === 'quoted') {
      if (c === '"') {
        if (raw[i + 1] === '"') { token += '"'; i++; }
        else state = 'afterQuote';
      } else token += c;
    } else if (state === 'afterQuote') {
      if (c === delimiter) { out.push(token); token = ''; state = 'start'; }
      else if (c === ' ' || (c === '\t' && delimiter !== '\t')) continue;
      else return null;
    } else if (c === delimiter) {
      out.push(token.trim()); token = ''; state = 'start';
    } else if (c === '"') {
      if (state !== 'start') return null;
      state = 'quoted';
    } else if (state === 'start' && (c === ' ' || (c === '\t' && delimiter !== '\t'))) {
      // Match the generated strict CSV parser's bounded field-edge stripping:
      // whitespace adjacent to a field is ignored, but quotes inside an
      // already-started unquoted value remain invalid.
      continue;
    } else {
      token += c;
      state = 'plain';
    }
  }
  if (state === 'quoted') return null;
  out.push(state === 'afterQuote' ? token : token.trim());
  return out;
}

export interface CsvColumnShape {
  columnCount:number;
  eventNumbers:number[];
}
export interface CsvShapeInspection {
  groups:CsvColumnShape[];
  invalidEventNumbers:number[];
}

/** Report structural CSV widths and source event numbers without field values.
 * Rows that cannot be safely tokenized are listed separately rather than
 * suppressing useful shape evidence from the rest of the sample. */
export function inspectCsvColumnShapes(
  input:string,delimiter:','|';'|'\t',limit=MAX_EVENTS,
):CsvShapeInspection{
  const bounded=Math.min(limit,MAX_EVENTS);
  const records=splitEvents(input,'single-line',bounded+1);
  if(!records.length||records.length>bounded)return {groups:[],invalidEventNumbers:[]};
  const groups=new Map<number,number[]>(),invalidEventNumbers:number[]=[];
  for(let index=0;index<records.length;index++){
    const values=tokenizeCSV(records[index]!.raw,delimiter);
    if(!values||values.length<2){invalidEventNumbers.push(index+1);continue;}
    const items=groups.get(values.length)??[];
    items.push(index+1);groups.set(values.length,items);
  }
  return {
    groups:[...groups.entries()]
      .map(([columnCount,eventNumbers])=>({columnCount,eventNumbers}))
      .sort((a,b)=>b.eventNumbers.length-a.eventNumbers.length||a.columnCount-b.columnCount),
    invalidEventNumbers,
  };
}
export function summarizeCsvColumnShapes(
  input:string,delimiter:','|';'|'\t',limit=MAX_EVENTS,
):CsvColumnShape[]{
  return inspectCsvColumnShapes(input,delimiter,limit).groups;
}

/** Infer only the number of columns in a homogeneous one-line CSV sample.
 * No vendor meaning or header semantics are inferred. */
export function inferConsistentCsvColumnCount(
  input:string,delimiter:','|';'|'\t',limit=MAX_EVENTS,
):number|null{
  const inspection=inspectCsvColumnShapes(input,delimiter,limit);
  const shapes=inspection.groups;
  return inspection.invalidEventNumbers.length===0&&shapes.length===1&&shapes[0]!.columnCount<=100?
    shapes[0]!.columnCount:null;
}

function extractCSV(raw: string, columns: string, delimiter: string): Extraction {
  if (![',', ';', '\t'].includes(delimiter)) {
    return { fields: {}, errors: ['Unsupported CSV data delimiter'] };
  }
  const names = columns.split(',').map((x) => x.trim());
  if (!names.length || names.length > 100 || names.some((x) => !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(x)) ||
      new Set(names).size !== names.length) {
    return { fields: {}, errors: ['Provide unique valid CSV column names'] };
  }
  const values = tokenizeCSV(raw, delimiter);
  if (!values) return { fields: {}, errors: ['Malformed CSV quotation or unsupported delimiter'] };
  if (values.length !== names.length) {
    return { fields: {}, errors: ['CSV column count mismatch: expected ' + names.length + ', received ' + values.length] };
  }
  return { fields: Object.fromEntries(names.map((name, i) => [name, values[i]])), errors: [] };
}

function extractSyslog(raw: string): Extraction {
  // Narrow, explicitly approximate RFC 5424 header; no claim of full Fluentd equivalence.
  const match = raw.match(/^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:-|\[[^\]]*\])\s+(.*)$/);
  if (!match) return { fields: {}, errors: ['Unsupported Syslog header; preview accepts a subset of RFC 5424'] };
  const priority = Number(match[1]);
  if (priority > 191) return { fields: {}, errors: ['Syslog priority must be 0..191'] };
  return {
    fields: {
      syslog_priority: priority, syslog_version: Number(match[2]), timestamp: match[3],
      host: match[4], app: match[5], procid: match[6], msgid: match[7], message: match[8],
    },
    errors: [],
  };
}


function extractRegex(raw: string, pattern: string): Extraction {
  const issue = validatePreviewRegexPattern(pattern);
  if (issue) return { fields: {}, errors: [issue] };
  try {
    const expression = new RegExp(pattern);
    const matched = expression.exec(raw);
    if (!matched?.groups) return { fields: {}, errors: ['Expression did not match this event'] };
    const fields = Object.fromEntries(Object.entries(matched.groups).filter(([, v]) => v !== undefined));
    if (!Object.keys(fields).length) return { fields: {}, errors: ['Named captures returned no fields'] };
    const temporalIssue=validateConventionalTemporalCaptures(fields);
    if(temporalIssue)return {fields:{},errors:[temporalIssue]};
    return { fields, errors: [] };
  } catch {
    return { fields: {}, errors: ['Invalid regular expression'] };
  }
}

export function extractFields(raw: string, format: ConcreteFormat, draft: ParserDraft): Extraction {
  switch (format) {
    case 'json': return extractJSON(raw);
    case 'kv': return extractKV(raw);
    case 'csv': return extractCSV(raw, draft.csvColumns, draft.csvDelimiter ?? ',');
    case 'java_stacktrace': return parseJavaStacktrace(raw);
    case 'generic_structural': return extractGenericStructural(raw,draft.genericStructuralProfile);
    case 'mixed': {
      const selected=draft.mixedFormats??[];
      if(selected.length<2||selected.length>4||
         new Set(selected).size!==selected.length||
         selected.some(f=>!['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef','csv'].includes(f)))
        return {fields:{},errors:['Select an explicit bounded mixed-family allowlist']};
      // Reuse the reviewed strict RFC5424 header + nested CEF/LEEF parser
      // for exact wrapper routing. A broken header must never fall back to KV.
      if(raw.startsWith('<')){
        if(/^<\d{1,3}>[A-Z][a-z]{2} /.test(raw)){
          // The strict TAG: parser verifies the yearless BSD header once,
          // then exactly one explicitly selected KV/CEF/LEEF body branch.
          const cef=extractStructuredFamily(raw,'syslog_rfc3164','cef');
          const leef=extractStructuredFamily(raw,'syslog_rfc3164','leef');
          const kv=extractStructuredFamily(raw,'syslog_rfc3164','kv');
          const mode=!cef.errors.length?'rfc3164_cef':
            !leef.errors.length?'rfc3164_leef':
            !kv.errors.length?'rfc3164_kv':null;
          if(!mode||!selected.includes(mode))
            return {fields:{},errors:['RFC3164 TAG body is unsupported or not allowlisted']};
          return mode==='rfc3164_cef'?cef:mode==='rfc3164_leef'?leef:kv;
        }
        const cef=extractStructuredFamily(raw,'syslog_rfc5424','cef');
        const leef=extractStructuredFamily(raw,'syslog_rfc5424','leef');
        const json=extractStructuredFamily(raw,'syslog_rfc5424','json');
        const kv=extractStructuredFamily(raw,'syslog_rfc5424','kv');
        const mode=!cef.errors.length?'rfc5424_cef':
          !leef.errors.length?'rfc5424_leef':
          !json.errors.length?'rfc5424_json':
          !kv.errors.length?'rfc5424_kv':null;
        if(!mode||!selected.includes(mode))
          return {fields:{},errors:['Wrapped Syslog is malformed or not in mixed allowlist']};
        return mode==='rfc5424_cef'?cef:mode==='rfc5424_leef'?leef:
          mode==='rfc5424_json'?json:kv;
      }
      // The backend router tests exact prefixes; do not silently trim or
      // accept a partial KV match elsewhere in the record.
      const family:typeof selected[number]|null=
        raw.startsWith('{')?'json':
        raw.startsWith('CEF:')?'cef':
        raw.startsWith('LEEF:')?'leef':
        /^[A-Za-z_][A-Za-z0-9_.-]*=/.test(raw)?'kv':
        selected.includes('csv')&&raw.includes(draft.csvDelimiter??',')?'csv':null;
      if(!family||!selected.includes(family))
        return {fields:{},errors:['Mixed event is unsupported or excluded by allowlist']};
      return family==='kv'?strictKeyValues(raw):
        family==='csv'?extractCSV(raw,draft.csvColumns,draft.csvDelimiter??','):
        extractFields(raw,family,draft);
    }
    case 'syslog': return extractSyslog(raw);
    case 'syslog_rfc3164':
    case 'syslog_rfc5424': return extractStructuredFamily(raw,format,
      draft.format==='auto'?'auto':(draft.syslogBodyFormat ?? 'raw'),draft.pattern);
    case 'cef':
    case 'leef': return extractStructuredFamily(raw, format);
    case 'regex': return extractRegex(raw, draft.pattern);
  }
}

function asIPv4(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part =>
    /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function asIP(value: string): boolean {
  if (!value.includes(':')) return asIPv4(value);
  // RFC 4291: exactly eight 16-bit groups, optionally shortened once by ::.
  // A dotted IPv4 tail consumes two groups. Reject zones and URL brackets:
  // neither is a literal IP value in the normalized Stellar metadata field.
  if (value.length > 45 || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  let address = value;
  if (address.includes('.')) {
    const separator = address.lastIndexOf(':');
    if (separator === -1 || !asIPv4(address.slice(separator + 1))) return false;
    address = address.slice(0, separator + 1) + '0:0';
  }
  const halves = address.split('::');
  if (halves.length > 2) return false;
  const groups = (text: string) => text ? text.split(':') : [];
  const left = groups(halves[0]!);
  const right = halves.length === 2 ? groups(halves[1]!) : [];
  const validGroup = (group: string) => /^[0-9a-fA-F]{1,4}$/.test(group);
  if (![...left, ...right].every(validGroup)) return false;
  const explicitGroups = left.length + right.length;
  return halves.length === 2 ? explicitGroups < 8 : explicitGroups === 8;
}

export function convertValue(raw: unknown, type: FieldType): { value?: unknown; error?: string } {
  if (raw === undefined || raw === null || (typeof raw === 'string' && !raw.trim())) return { error: 'Missing value' };
  const value = typeof raw === 'string' ? raw.trim() : String(raw);
  switch (type) {
    case 'string':
      return { value: typeof raw === 'object' ? JSON.stringify(raw) : String(raw) };
    case 'integer':
      return /^-?\d+$/.test(value) && Number.isSafeInteger(Number(value)) ? { value: Number(value) } : { error: 'Expected safe integer' };
    case 'number':
      return value !== '' && Number.isFinite(Number(value)) ? { value: Number(value) } : { error: 'Expected finite number' };
    case 'boolean':
      if (/^(?:true|1)$/i.test(value)) return { value: true };
      if (/^(?:false|0)$/i.test(value)) return { value: false };
      return { error: 'Expected boolean (true/false/1/0)' };
    case 'port':
      return /^\d+$/.test(value) && Number(value) <= 65535 ? { value: Number(value) } : { error: 'Expected port 0..65535' };
    case 'ip':
      return asIP(value) ? { value } : { error: 'Expected valid IP address' };
    case 'timestamp':
      return /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value))
        ? { value: new Date(value).toISOString() } : { error: 'Expected ISO timestamp with explicit timezone' };
  }
}

export function splitEvents(input: string, boundary: EventBoundary = 'single-line', limit = MAX_EVENTS): { raw: string; line: number }[] {
  const lines = input.replace(/\r\n?/g, '\n').split('\n');
  const maximum = Math.max(0, Math.min(Math.floor(limit), MAX_EVENTS + 1));
  if (boundary === 'single-line') {
    return lines.map((raw, i) => ({ raw, line: i + 1 })).filter(({ raw }) => raw.trim().length > 0).slice(0, maximum);
  }
  // Every blank physical line ends the current logical record. Nothing executes here.
  const records: { raw: string; line: number }[] = [];
  let parts: string[] = [];
  let firstLine = 1;
  const flush = () => {
    if (parts.length) records.push({ raw: parts.join('\n'), line: firstLine });
    parts = [];
  };
  for (let i = 0; i < lines.length && records.length < maximum; i++) {
    const raw = lines[i];
    if (!raw.trim()) {
      flush();
    } else {
      if (!parts.length) firstLine = i + 1;
      parts.push(raw);
    }
  }
  if (parts.length && records.length < maximum) flush();
  return records;
}

function processEvent(raw: string, line: number, index: number, draft: ParserDraft, boundary: EventBoundary = 'single-line'): EventResult {
  const wrapped=inspectDeclaredForwarders(raw,draft.forwarder);
  const eventSource=wrapped.status==='UNWRAPPED'?wrapped.payload:raw;
  const detected = detectFormat(eventSource);
  const effectiveFormat = draft.format === 'auto' ? detected.format : draft.format;
  const diagnostics: Diagnostic[] = [];
  const trace: TraceStep[] = [];
  const error = (stage: Diagnostic['stage'], code: string, message: string, field?: string) =>
    diagnostics.push({ stage, severity: 'error', code, message, field });
  trace.push({ stage: 'Event boundary', detail: boundary === 'blank-line' ? 'Blank-line grouped event beginning on physical line ' + line : 'Physical line ' + line, ok: true });
  trace.push({ stage: 'Detection', detail: detected.format + ' · ' + detected.reason, ok: detected.format !== 'unknown' });
  let fields: Record<string, unknown> = {};
  let matched = false;
  if (raw.length > MAX_LINE_CHARS) {
    error('break', 'LINE_TOO_LONG', 'Event exceeds ' + MAX_LINE_CHARS + ' characters');
  } else if(wrapped.status==='ABSTAIN_UNSAFE'){
    error('extract','UNSAFE_RELAY_ENVELOPE','The forwarded log cannot be safely unwrapped.');
  } else if (effectiveFormat === 'unknown') {
    error('detect', 'UNSUPPORTED_FORMAT', 'No supported format. Choose a format or create a regex rule.');
  } else {
    const extraction = extractFields(eventSource, effectiveFormat, draft);
    extraction.errors.forEach((message) => error('extract', 'EXTRACTION_FAILED', message));
    fields = extraction.fields;
    matched = Object.keys(fields).length > 0;
  }
  trace.push({ stage: 'Extraction', detail: matched ? Object.keys(fields).length + ' fields extracted' : 'No fields extracted', ok: matched });
  const normalized: Record<string, unknown> = draft.format==='generic_structural'
    ? {parserstudio_source:draft.omitSourceRaw===true?withoutSourceRaw(fields) as Record<string,unknown>:fields}
    : {};
  const family=inspectEventProfile(fields,draft.eventProfiles);
  if(draft.eventProfiles&&!family.profile)
    error('normalize','UNRECOGNIZED_EVENT_FAMILY',
      'Event type is missing, ambiguous or not in the reviewed family list.');
  if(family.profile)normalized.parserstudio_event_family=family.name;
  if(wrapped.status==='UNWRAPPED') {
    normalized.parserstudio_transport={forwarder_hops:wrapped.hops.map(hop=>({
      relay_host:hop.relayHost,relay_timestamp:hop.relayTimestamp,
      envelope:hop.format,prefix_start_byte:hop.prefixStartByte,
      payload_start_byte:hop.payloadStartByte,
    }))};
    trace.push({stage:'Forwarder envelope',
      detail:wrapped.hops.length+' declared relay hop(s); received source bytes preserved',
      ok:true});
  }
  const mapped = new Set<string>();
  for (const mapping of [...draft.mappings,...(family.profile?.mappings??[])]) {
    const source = mapping.source.trim();
    const target = mapping.target.trim();
    if (!source || !VALID_TARGET.test(target) ||
        target.split('.').some(part=>UNSAFE_OUTPUT_SEGMENTS.has(part))) {
      error('normalize', 'INVALID_MAPPING', 'Invalid source or output field', mapping.id);
      continue;
    }
    const sourceValue = lookupFieldValue(fields, source);
    if (!sourceValue.found) {
      diagnostics.push({ stage: 'normalize', severity: 'warning', code: 'SOURCE_NOT_FOUND', message: 'Source field is absent: ' + source, field: source });
      continue;
    }
    // Match the backend DRAFT runtime: ignored source values remain preserved
    // in Generic Structural parserstudio_source, but are not coerced/mapped.
    if (sourceValue.value === null || sourceValue.value === undefined ||
        ['', 'N/A', '-'].includes(String(sourceValue.value))) {
      mapped.add(source);
      continue;
    }
    mapped.add(source);
    const converted = convertValue(sourceValue.value, mapping.type);
    if (converted.error) {
      error('normalize', 'TYPE_ERROR', source + ': ' + converted.error, source);
      continue;
    }
    const group=draft.guided?.groups[mapping.id]??'vendor_fields';
    if(group!=='vendor_fields'&&
       !meetsStellar7ValueConstraints(target,sourceValue.value,converted.value)){
      error('normalize','TYPE_ERROR',
        source+': value does not satisfy the reviewed Stellar 7.0 field constraints',source);
      continue;
    }
    let container=normalized;
    if(group==='vendor_fields'){
      const vendor=draft.vendor.trim()||'vendor';
      const existing=Object.prototype.hasOwnProperty.call(normalized,vendor)?normalized[vendor]:undefined;
      if(existing!==undefined&&(!existing||typeof existing!=='object'||Array.isArray(existing))){
        error('normalize','TARGET_COLLISION','Vendor namespace collides with an existing output: '+vendor,target);
        continue;
      }
      if(existing===undefined){
        const vendorObject:Record<string,unknown>={};
        ownSet(normalized,vendor,vendorObject);
        container=vendorObject;
      }else container=existing as Record<string,unknown>;
    }
    if(normalizedPathExists(container,target)){
      error('normalize', 'TARGET_COLLISION', 'Output field is mapped more than once: ' + target, target);
      continue;
    }
    if(!assignNormalizedPath(container,target,converted.value)){
      error('normalize','INVALID_MAPPING','Could not assign output field: '+target,target);
    }
  }
  // Preview the reviewed declarative enrichment steps in order, never Ruby.
  // Dotted paths use the same nested lookup/assignment semantics as the
  // generated backend parser instead of creating literal "a.b" object keys.
  for (const [index, rule] of (draft.guided?.enrichment ?? []).entries()) {
    const step=index+1;
    const safeOutput=(target:string)=>VALID_TARGET.test(target)&&
      !normalizedPathExists(normalized,target)&&
      !target.split('.').some((part)=>UNSAFE_OUTPUT_SEGMENTS.has(part));
    const validDelimiter=(value:string|undefined)=>typeof value==='string'&&value.length>=1&&value.length<=8&&
      !/[\u0000-\u001f\u007f]/.test(value);
    if(rule.operator==='split_field'){
      const sourceResult=lookupFieldValue(normalized,rule.source),targets=rule.targets??[];
      const source=sourceResult.found?sourceResult.value:undefined;
      if(typeof source!=='string'){
        error('normalize','ENRICHMENT_SOURCE','Split source must be an existing string field at step '+step);continue;
      }
      if(!validDelimiter(rule.delimiter)||targets.length<2||targets.length>8||
         new Set(targets).size!==targets.length||targets.some(target=>!safeOutput(target))){
        error('normalize','ENRICHMENT_TARGET','Unsafe split rule at step '+step);continue;
      }
      const parts=source.split(rule.delimiter!);
      if(parts.length!==targets.length){
        error('normalize','ENRICHMENT_TYPE','Split field count mismatch at step '+step);continue;
      }
      if(targets.some((target,i)=>!assignNormalizedPath(normalized,target,parts[i]!))){
        error('normalize','ENRICHMENT_TARGET','Could not assign split output at step '+step);
      }
      continue;
    }
    if(rule.operator==='merge_fields'){
      const sources=rule.sources??[],target=rule.target.trim();
      if(!validDelimiter(rule.delimiter)||sources.length<2||sources.length>8||
         new Set(sources).size!==sources.length||!safeOutput(target)){
        error('normalize','ENRICHMENT_TARGET','Unsafe merge rule at step '+step);continue;
      }
      const values=sources.map(source=>{
        const found=lookupFieldValue(normalized,source);
        return found.found?found.value:undefined;
      });
      if(values.some(value=>typeof value!=='string')){
        error('normalize','ENRICHMENT_SOURCE','Merge sources must be existing string fields at step '+step);continue;
      }
      if(!assignNormalizedPath(normalized,target,(values as string[]).join(rule.delimiter!)))
        error('normalize','ENRICHMENT_TARGET','Could not assign merge output at step '+step);
      continue;
    }
    const target = rule.target.trim();
    if (!safeOutput(target)) {
      error('normalize', 'ENRICHMENT_TARGET', 'Unsafe or duplicate enrichment output at step ' + step);
      continue;
    }
    if (rule.operator === 'set_const') {
      if(!assignNormalizedPath(normalized,target,rule.value))
        error('normalize','ENRICHMENT_TARGET','Could not assign constant output at step '+step);
      continue;
    }
    const sourceResult=lookupFieldValue(normalized,rule.source);
    if (!sourceResult.found) {
      error('normalize', 'ENRICHMENT_SOURCE', 'Source field unavailable at step ' + step);
      continue;
    }
    const source = sourceResult.value;
    if (rule.operator === 'copy') {
      if(!assignNormalizedPath(normalized,target,source))
        error('normalize','ENRICHMENT_TARGET','Could not assign copied output at step '+step);
    } else if (rule.operator === 'lowercase' || rule.operator === 'uppercase') {
      if (typeof source !== 'string') {
        error('normalize', 'ENRICHMENT_TYPE', 'Text transform requires a string source');
        continue;
      }
      const value=rule.operator === 'lowercase' ? source.toLowerCase() : source.toUpperCase();
      if(!assignNormalizedPath(normalized,target,value))
        error('normalize','ENRICHMENT_TARGET','Could not assign transformed output at step '+step);
    } else error('normalize', 'ENRICHMENT_UNSUPPORTED', 'Unsupported enrichment operator');
  }
  const unmapped = Object.keys(fields).filter((field) => !mapped.has(field));
  if (unmapped.length) diagnostics.push({ stage: 'normalize', severity: 'warning', code: 'UNMAPPED_FIELDS', message: unmapped.length + ' source fields remain available without mappings' });
  const hasErrors = diagnostics.some((issue) => issue.severity === 'error');
  const normalizedOk = matched && Object.keys(normalized).length > 0 && !hasErrors;
  if (matched && !draft.mappings.length) {
    diagnostics.push({ stage: 'normalize', severity: 'warning', code: 'NO_MAPPINGS', message: 'No output mapping has been defined' });
  }
  trace.push({ stage: 'Normalization', detail: Object.keys(normalized).length + ' mapped fields', ok: normalizedOk });
  trace.push({ stage: 'Compatibility', detail: 'Browser approximation only; no Fluentd or Stellar import test', ok: false });
  return {
    id: 'event-' + (index + 1), line, raw, detected, effectiveFormat, fields, normalized, unmapped,
    ...(draft.eventProfiles?{eventFamily:family.name}:{}),
    ...(wrapped.hops.length?{forwarderHops:wrapped.hops}:{}),
    matched, extracted: matched, normalizedOk,
    status: hasErrors || !matched ? 'fail' : diagnostics.length ? 'warning' : 'pass',
    diagnostics, trace,
  };
}

/** Mirrors the generated Ruby helper: drop every `source_raw` key from the lossless source projection. */
function withoutSourceRaw(value:unknown):unknown{
  if(Array.isArray(value))return value.map(withoutSourceRaw);
  if(value&&typeof value==='object')
    return Object.fromEntries(Object.entries(value as Record<string,unknown>)
      .filter(([key])=>key!=='source_raw').map(([key,item])=>[key,withoutSourceRaw(item)]));
  return value;
}

export function preview(input: string, draft: ParserDraft): SuiteResult {
  const length = new TextEncoder().encode(input).length;
  if (length > MAX_DATASET_BYTES) {
    const event = processEvent('', 1, 0, draft);
    event.raw = '';
    event.fields = {};
    event.normalized = {};
    event.matched = false;
    event.extracted = false;
    event.normalizedOk = false;
    event.diagnostics = [{ stage: 'break', severity: 'error', code: 'DATASET_TOO_LARGE', message: 'Dataset exceeds 64 KiB' }];
    event.trace = [{ stage: 'Event boundary', detail: 'Dataset rejected before execution', ok: false }];
    return {
      events: [event],
      counts: { total: 1, matched: 0, extracted: 0, normalized: 0, failures: 1, warnings: 0 },
      engine: 'browser-preview', nativeFluentdVerified: false, stellarExportVerified: false,
    };
  }
  const boundary = draft.guided?.eventBoundary ?? 'single-line';
  const allRecords = splitEvents(input, boundary, MAX_EVENTS + 1);
  const records = allRecords.slice(0, MAX_EVENTS);
  const events = records.map(({ raw, line }, i) => processEvent(raw, line, i, draft, boundary));
  if (allRecords.length > MAX_EVENTS) {
    const last = events[events.length - 1];
    if (last) {
      last.diagnostics.push({ stage: 'break', severity: 'warning', code: 'EVENT_LIMIT', message: 'Preview limited to first ' + MAX_EVENTS + ' logical events' });
      if (last.status === 'pass') last.status = 'warning';
    }
  }
  const counts = {
    total: events.length, matched: events.filter((x) => x.matched).length,
    extracted: events.filter((x) => x.extracted).length,
    normalized: events.filter((x) => x.normalizedOk).length,
    failures: events.filter((x) => x.status === 'fail').length,
    warnings: events.filter((x) => x.status === 'warning').length,
  };
  return { events, counts, engine: 'browser-preview', nativeFluentdVerified: false, stellarExportVerified: false };
}

export function formatLabel(format: Format | 'unknown'): string {
  const labels: Record<Format | 'unknown', string> = {
    auto: 'Auto detect', json: 'JSON', kv: 'Key / Value', csv: 'CSV',
    mixed:'Mixed JSON / KV / CEF / LEEF (strict)',
    java_stacktrace:'Java Exception Stack Trace (TCP LF LF framed)',
    generic_structural:'Generic Structural (bounded recovery)',
    syslog_rfc3164: 'RFC3164 (year/zone unknown)',
    syslog_rfc5424: 'RFC5424', cef: 'CEF', leef: 'LEEF',
    syslog: 'Syslog (preview)', regex: 'Regex', unknown: 'Unrecognized',
  };
  return labels[format];
}
