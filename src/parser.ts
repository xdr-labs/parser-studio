import {meetsStellar7ValueConstraints,officialProtocolPairConflict} from './stellar7ValueConstraints';
import type { ConcreteFormat, Detection, Diagnostic, EventParseStatus, EventResult, Format, ParserDraft, SuiteResult, TraceStep } from './model';
import { classifyStructuredParse } from './grammar/parseStatus';
import { bodyKindOf, detectStructuredFamily, extractStructuredFamily,strictKeyValues } from './structuredFamilies';
import { hasAmbiguousFieldPath,lookupFieldValue,mappingWhenApplies } from './fieldPaths';
import {parseJavaStacktrace} from './javaStacktrace';
import {coerceCanonicalValue as convertValue} from '../backend/src/canonical-value-contract';
import {jsonSourceValueValid} from './jsonSourceSafety';
import {findStellarMetadataField} from './guided/stellarMetadataCatalog';
import {extractGenericStructural} from './genericStructural';
import type { EventBoundary } from './guided/contract';
import {inspectDeclaredForwarders} from './guided/declaredForwarder';
import {inspectEventProfile} from './guided/multiEventRouting';
import {hasDuplicateJsonObjectKeys} from './jsonDuplicateKeys';
import {hasUnsafeJsonNumbers} from './jsonNumberSafety';
import {extractPortableRegexFields as extractRegex} from './portableRegexExtraction';
import {canonicalCaseTransform,canonicalIgnoreSourceValue} from '../backend/src/canonical-operator-contract';

export const MAX_DATASET_BYTES = 64 * 1024;
export const MAX_EVENTS = 500;
// Security products such as EDR/XDR can emit valid single-line JSON records well above 4 KiB.
// The dataset is already hard-bounded to 64 KiB, so do not reject one valid record earlier.
export const MAX_LINE_CHARS = MAX_DATASET_BYTES;
const VALID_TARGET = /^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
const UNSAFE_OUTPUT_SEGMENTS=new Set(['__proto__','constructor','prototype']);
const RUNTIME_OUTPUT_ROOTS=new Set([
  'parserstudio_source','parserstudio_event_family','parserstudio_transport',
  'stellar_log_index','msg_origin','parser_err_msg','parser_err_stage','parser_err_field',
]);

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
    if(hasUnsafeJsonNumbers(raw))
      return {fields:{},errors:['Unsafe JSON numeric precision: quote large integer identifiers as strings before mapping']};
    if(!jsonSourceValueValid(parsed))
      return {fields:{},errors:['JSON source exceeds the native nesting limit or has an invalid Unicode surrogate']};
    return { fields: parsed as Record<string, unknown>, errors: [] };
  } catch {
    return { fields: {}, errors: ['Invalid JSON object'] };
  }
}

function extractKV(raw: string): Extraction {
  // Use the same complete, bounded grammar as Syslog KV and generated Ruby.
  // A partial regex match must never conceal an unmatched source fragment.
  return strictKeyValues(raw);
}

export function tokenizeCSV(raw: string, delimiter: string): (string | null)[] | null {
  // The backend compiles Ruby CSV.parse_line with liberal_parsing: false.
  // This browser subset is intentionally conservative; malformed quoted
  // cells never become successful evidence for native generation.
  if (![',', ';', '\t'].includes(delimiter)) return null;
  const out: (string | null)[] = [];
  // The generated Ruby uses strip:false for TAB CSV because Ruby CSV 3.2
  // cannot combine strip:true with a TAB column separator. Retain TAB-space
  // cells exactly, including whitespace-only values (not missing/null).
  const stripUnquoted = delimiter !== '\t';
  // Ruby CSV strip:true removes ASCII whitespace, not Unicode NBSP/EM SPACE.
  // Preserve source Unicode values to keep browser/native mapped fields equal.
  const trimCsvAscii=(text:string)=>text.replace(/^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g,'');
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
      else if (stripUnquoted && (c === ' ' || c === '\t')) continue;
      else return null;
    } else if (c === delimiter) {
      out.push(state === 'start' ? null : stripUnquoted ? trimCsvAscii(token) : token);
      token = ''; state = 'start';
    } else if (c === '"') {
      if (state !== 'start') return null;
      state = 'quoted';
    } else if (state === 'start' && stripUnquoted && (c === ' ' || c === '\t')) {
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
  out.push(state === 'start' ? null : state === 'afterQuote' ? token :
    stripUnquoted ? trimCsvAscii(token) : token);
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

export {convertValue};

export function splitEvents(input: string, boundary: EventBoundary = 'single-line', limit = MAX_EVENTS): { raw: string; line: number }[] {
  const lines = input.replace(/\r\n/g, '\n').split('\n');
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
  let parseStatus: EventParseStatus = 'UNKNOWN';
  if (raw.length > MAX_LINE_CHARS) {
    error('break', 'LINE_TOO_LONG', 'Event exceeds ' + MAX_LINE_CHARS + ' characters');
  } else if(new TextEncoder().encode(raw).byteLength>(draft.guided?.receiver.messageLimit??65536)){
    error('break','MESSAGE_LIMIT','Source event exceeds the configured receiver byte limit');
  } else if(raw.includes('\r')){
    error('break','UNSUPPORTED_LINE_ENDING','Bare carriage returns are not approved event delimiters');
  } else if(wrapped.status==='ABSTAIN_UNSAFE'){
    error('extract','UNSAFE_RELAY_ENVELOPE','The forwarded log cannot be safely unwrapped.');
  } else if (effectiveFormat === 'unknown') {
    error('detect', 'UNSUPPORTED_FORMAT', 'No supported format. Choose a format or create a regex rule.');
  } else {
    const extraction = extractFields(eventSource, effectiveFormat, draft);
    extraction.errors.forEach((message) => error('extract', 'EXTRACTION_FAILED', message));
    fields = extraction.fields;
    matched = Object.keys(fields).length > 0;
    // Parsing Success Contract: the extractor's own "no errors" is not proof. For a key=value body the
    // original line is re-read by an independent tokenizer, and a pair that is visible there but missing
    // from the result makes the event PARTIAL - reported as a failure, never as a complete parse.
    // A key=value body is known either from the draft (format kv, or Syslog with body kv) or from what the
    // extractor says it parsed (bodyKindOf: an `auto` body that resolved to key=value, the key=value
    // branches of a mixed allowlist). Either one is enough, so the check cannot be skipped by losing the tag.
    const keyValueBody = effectiveFormat === 'kv' || bodyKindOf(extraction) === 'kv' ||
      ((effectiveFormat === 'syslog_rfc3164' || effectiveFormat === 'syslog_rfc5424') && draft.format !== 'auto' && draft.syslogBodyFormat === 'kv');
    const verdict = classifyStructuredParse(eventSource, extraction, keyValueBody ? 'kv' : 'other');
    parseStatus = verdict.status;
    if (verdict.status === 'PARTIAL' && verdict.lostPairs.length > 0)
      error('extract', 'FIELD_LOSS_NOT_FULL',
        'A key=value pair of the original log is missing from the parsed result: ' +
        verdict.lostPairs.slice(0, 5).map(pair => pair.key).join(', ') + '. The event is not treated as fully parsed.');
    else if (verdict.status === 'PARTIAL')
      error('extract', 'HEADER_MISREAD_NOT_FULL',
        'The Syslog header was not read correctly: ' + verdict.reasons.join('; ') + '. The event is not treated as fully parsed.');
  }
  trace.push({ stage: 'Extraction', detail: matched ? Object.keys(fields).length + ' fields extracted' : 'No fields extracted', ok: matched });
  const normalized: Record<string, unknown> = draft.format==='generic_structural'&&matched
    ? {parserstudio_source:structuredClone(draft.omitSourceRaw===true?withoutSourceRaw(fields):fields)}
    : {};
  const family=inspectEventProfile(fields,draft.eventProfiles);
  if(draft.eventProfiles&&!family.profile)
    error('normalize','UNRECOGNIZED_EVENT_FAMILY',
      'Event type is missing, ambiguous or not in the reviewed family list.');
  if(family.profile)normalized.parserstudio_event_family=family.name;
  if(wrapped.status==='UNWRAPPED'&&matched) {
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
    if(!mappingWhenApplies(fields,mapping.when))continue;
    const source = mapping.source.trim();
    const target = mapping.target.trim();
    if (!source || !VALID_TARGET.test(target) ||
        target.split('.').some(part=>UNSAFE_OUTPUT_SEGMENTS.has(part))) {
      error('normalize', 'INVALID_MAPPING', 'Invalid source or output field', mapping.id);
      continue;
    }
    if(hasAmbiguousFieldPath(fields,source)){
      error('normalize','AMBIGUOUS_SOURCE_PATH',
        'A dotted key and a nested field share the same source path; choose an unambiguous log structure.',source);
      continue;
    }
    const sourceValue = lookupFieldValue(fields, source, mapping.sourcePathKind);
    if (!sourceValue.found) {
      diagnostics.push({ stage: 'normalize', severity: 'warning', code: 'SOURCE_NOT_FOUND', message: 'Source field is absent: ' + source, field: source });
      continue;
    }
    // Match the backend DRAFT runtime: ignored source values remain preserved
    // in Generic Structural parserstudio_source, but are not coerced/mapped.
    if (canonicalIgnoreSourceValue(sourceValue.value,['','N/A','-'])) {
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
    if(RUNTIME_OUTPUT_ROOTS.has(target.split('.')[0]!)){
      error('normalize','TARGET_COLLISION','System-owned output field is reserved: '+target,target);
      continue;
    }
    let container=normalized;
    if(group==='vendor_fields'){
      const vendor=draft.vendor.trim()||'vendor';
      if(RUNTIME_OUTPUT_ROOTS.has(vendor)){
        error('normalize','TARGET_COLLISION','Manufacturer conflicts with a reserved parser namespace: '+vendor,target);
        continue;
      }
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
  // Native Ruby checks typed protocol-pair semantics at normalization exit.
  // A contradiction in mapped values must not be blamed on enrichment.
  if(matched&&!diagnostics.some(issue=>issue.severity==='error')&&
     officialProtocolPairConflict(normalized.proto,normalized.proto_name))
    error('normalize','PROTOCOL_CONFLICT',
      'The normalized IP protocol number contradicts its Layer 4 name.');
  // Native Ruby only starts enrichment after successful extraction and mapping.
  // It executes enrichment against a deep copy; any failure leaves the
  // pre-enrichment normalized fields untouched in its diagnostic callback.
  const canEnrich=matched&&!diagnostics.some(issue=>issue.severity==='error');
  const preEnrichment=canEnrich?structuredClone(normalized):null;
  // Dotted paths share the bounded source lookup contract with native Ruby.
  for (const [index, rule] of (canEnrich?draft.guided?.enrichment??[]:[]).entries()) {
    const step=index+1;
    const safeOutput=(target:string)=>VALID_TARGET.test(target)&&
      !RUNTIME_OUTPUT_ROOTS.has(target.split('.')[0]!)&&
      !normalizedPathExists(normalized,target)&&
      !target.split('.').some((part)=>UNSAFE_OUTPUT_SEGMENTS.has(part));
    const validDelimiter=(value:string|undefined)=>typeof value==='string'&&value.length>=1&&value.length<=8&&
      !/[\u0000-\u001f\u007f]/.test(value);
    if(rule.operator==='split_field'){
      const sourceResult=lookupFieldValue(normalized,rule.source),targets=rule.targets??[];
      const source=sourceResult.found?sourceResult.value:undefined;
      if(typeof source!=='string'){
        error('enrichment','ENRICHMENT_SOURCE','Split source must be an existing string field at step '+step);continue;
      }
      if(!validDelimiter(rule.delimiter)||targets.length<2||targets.length>8||
         new Set(targets).size!==targets.length||targets.some(target=>!safeOutput(target))){
        error('enrichment','ENRICHMENT_TARGET','Unsafe split rule at step '+step);continue;
      }
      const parts=source.split(rule.delimiter!);
      if(parts.length!==targets.length){
        error('enrichment','ENRICHMENT_TYPE','Split field count mismatch at step '+step);continue;
      }
      if(targets.some((target,i)=>!assignNormalizedPath(normalized,target,parts[i]!))){
        error('enrichment','ENRICHMENT_TARGET','Could not assign split output at step '+step);
      }
      continue;
    }
    if(rule.operator==='merge_fields'){
      const sources=rule.sources??[],target=rule.target.trim();
      if(!validDelimiter(rule.delimiter)||sources.length<2||sources.length>8||
         new Set(sources).size!==sources.length||!safeOutput(target)){
        error('enrichment','ENRICHMENT_TARGET','Unsafe merge rule at step '+step);continue;
      }
      const values=sources.map(source=>{
        const found=lookupFieldValue(normalized,source);
        return found.found?found.value:undefined;
      });
      if(values.some(value=>typeof value!=='string')){
        error('enrichment','ENRICHMENT_SOURCE','Merge sources must be existing string fields at step '+step);continue;
      }
      if(!assignNormalizedPath(normalized,target,(values as string[]).join(rule.delimiter!)))
        error('enrichment','ENRICHMENT_TARGET','Could not assign merge output at step '+step);
      continue;
    }
    const target = rule.target.trim();
    if (!safeOutput(target)) {
      error('enrichment', 'ENRICHMENT_TARGET', 'Unsafe or duplicate enrichment output at step ' + step);
      continue;
    }
    if (rule.operator === 'set_const') {
      if(!assignNormalizedPath(normalized,target,rule.value))
        error('enrichment','ENRICHMENT_TARGET','Could not assign constant output at step '+step);
      continue;
    }
    const sourceResult=lookupFieldValue(normalized,rule.source);
    if (!sourceResult.found) {
      error('enrichment', 'ENRICHMENT_SOURCE', 'Source field unavailable at step ' + step);
      continue;
    }
    const source = sourceResult.value;
    if (rule.operator === 'copy') {
      if(!assignNormalizedPath(normalized,target,source))
        error('enrichment','ENRICHMENT_TARGET','Could not assign copied output at step '+step);
    } else if (rule.operator === 'lowercase' || rule.operator === 'uppercase') {
      if (typeof source !== 'string') {
        error('enrichment', 'ENRICHMENT_TYPE', 'Text transform requires a string source');
        continue;
      }
      const value=canonicalCaseTransform(source,rule.operator);
      if(!assignNormalizedPath(normalized,target,value))
        error('enrichment','ENRICHMENT_TARGET','Could not assign transformed output at step '+step);
    } else error('enrichment', 'ENRICHMENT_UNSUPPORTED', 'Unsupported enrichment operator');
  }
  // The native DRAFT validates every final enriched official field.
  // A successful browser mapping must not hide invalid enrichment output.
  const enrichedTargets=(canEnrich?draft.guided?.enrichment??[]:[]).flatMap(rule=>
    rule.operator==='split_field'?(rule.targets??[]):[rule.target]);
  for(const target of enrichedTargets){
    const vendorNamespace=draft.vendor.trim()||'vendor';
    if(target===vendorNamespace||target.startsWith(vendorNamespace+'.'))continue;
    const meta=findStellarMetadataField(target);
    if(!meta?.mappable||!meta.mappingType)continue;
    const found=lookupFieldValue(normalized,target);
    if(!found.found)continue;
    const value=found.value;
    const type=meta.mappingType;
    const basic=type==='string'?typeof value==='string':
      type==='integer'?typeof value==='number'&&Number.isSafeInteger(value):
      type==='port'?typeof value==='number'&&Number.isSafeInteger(value)&&value>=0&&value<=65535:
      type==='number'?typeof value==='number'&&Number.isFinite(value):
      type==='boolean'?typeof value==='boolean':
      type==='ip'?typeof value==='string'&&!convertValue(value,'ip').error:
      type==='timestamp'?typeof value==='string'&&!convertValue(value,'timestamp').error:
      false;
    if(!basic||!meetsStellar7ValueConstraints(target,value,value))
      error('enrichment','ENRICHMENT_TYPE','Enriched official field violates Stellar 7.0 scalar rules: '+target,target);
  }
  if(canEnrich&&officialProtocolPairConflict(normalized.proto,normalized.proto_name))
    error('enrichment','PROTOCOL_CONFLICT',
      'The final IP protocol number contradicts the reviewed Layer 4 protocol name.');
  if(preEnrichment&&diagnostics.some(issue=>issue.severity==='error'&&
    (issue.code.startsWith('ENRICHMENT_')||issue.code==='PROTOCOL_CONFLICT'))){
    // Do not leave a partially applied split, earlier successful constant or
    // invalid official value in a browser preview that native Ruby rolls back.
    for(const key of Object.keys(normalized))delete normalized[key];
    for(const [key,value] of Object.entries(preEnrichment))ownSet(normalized,key,value);
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
    parseStatus,
    status: hasErrors || !matched ? 'fail' : diagnostics.length ? 'warning' : 'pass',
    diagnostics, trace,
  };
}

/** Drop only whole-line copies owned by Generic Structural grammar nodes.
 * Manufacturer fields such as generic.kv.source_raw must remain unchanged. */
function withoutSourceRaw(value:unknown):unknown{
  if(!value||typeof value!=='object'||Array.isArray(value))return value;
  const synthetic=new Set(['generic','watchguard_message','session_envelope',
    'asa','juniper','watchguard']);
  return Object.fromEntries(Object.entries(value as Record<string,unknown>).map(([key,item])=>{
    if(synthetic.has(key)&&item&&typeof item==='object'&&!Array.isArray(item))
      return [key,Object.fromEntries(Object.entries(item as Record<string,unknown>)
        .filter(([field])=>field!=='source_raw'))];
    return [key,item];
  }));
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
