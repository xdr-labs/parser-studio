import type { ConcreteFormat, Detection, Diagnostic, EventResult, FieldType, Format, ParserDraft, SuiteResult, TraceStep } from './model';
import { detectStructuredFamily, extractStructuredFamily,strictKeyValues } from './structuredFamilies';
import { lookupFieldValue } from './fieldPaths';
import {parseJavaStacktrace} from './javaStacktrace';
import { validatePreviewRegexPattern } from './regexSafety';
import {extractGenericStructural} from './genericStructural';
import type { EventBoundary } from './guided/contract';
import {isIpToken,isPortToken} from './networkTokens';
import {readCsvSourceCells,type CsvSourceDelimiter} from './csvSourceCells';

export const MAX_DATASET_BYTES = 64 * 1024;
export const MAX_EVENTS = 500;
// Security products such as EDR/XDR can emit valid single-line JSON records well above 4 KiB.
// The dataset is already hard-bounded to 64 KiB, so do not reject one valid record earlier.
export const MAX_LINE_CHARS = MAX_DATASET_BYTES;
const VALID_TARGET = /^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*$/;

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

function tokenizeCSV(raw: string,delimiter: string):string[]|null{
  if(![',',';','\t'].includes(delimiter)||/[\r\n]/.test(raw)||
     new TextEncoder().encode(raw).byteLength>MAX_DATASET_BYTES)return null;
  const cells=readCsvSourceCells(raw,delimiter as CsvSourceDelimiter);
  return cells?cells.map(cell=>cell.value??''):null;
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
    case 'generic_structural': return extractGenericStructural(raw);
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
      return isPortToken(value) ? { value: Number(value) } : { error: 'Expected port 0..65535' };
    case 'ip':
      return isIpToken(value) ? { value } : { error: 'Expected valid IP address' };
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
  const detected = detectFormat(raw);
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
  } else if (effectiveFormat === 'unknown') {
    error('detect', 'UNSUPPORTED_FORMAT', 'No supported format. Choose a format or create a regex rule.');
  } else {
    const extraction = extractFields(raw, effectiveFormat, draft);
    extraction.errors.forEach((message) => error('extract', 'EXTRACTION_FAILED', message));
    fields = extraction.fields;
    matched = Object.keys(fields).length > 0;
  }
  trace.push({ stage: 'Extraction', detail: matched ? Object.keys(fields).length + ' fields extracted' : 'No fields extracted', ok: matched });
  const normalized: Record<string, unknown> = draft.format==='generic_structural'
    ? {parserstudio_source:fields}
    : {};
  const mapped = new Set<string>();
  for (const mapping of draft.mappings) {
    const source = mapping.source.trim();
    const target = mapping.target.trim();
    if (!source || !VALID_TARGET.test(target)) {
      error('normalize', 'INVALID_MAPPING', 'Invalid source or output field', mapping.id);
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(normalized, target)) {
      error('normalize', 'TARGET_COLLISION', 'Output field is mapped more than once: ' + target, target);
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
    if (converted.error) error('normalize', 'TYPE_ERROR', source + ': ' + converted.error, source);
    else normalized[target] = converted.value;
  }
  // Preview the reviewed declarative enrichment steps in order, never Ruby.
  for (const [index, rule] of (draft.guided?.enrichment ?? []).entries()) {
    const step=index+1;
    const safeOutput=(target:string)=>VALID_TARGET.test(target)&&
      !Object.prototype.hasOwnProperty.call(normalized,target)&&
      !target.split('.').some((part)=>['__proto__','constructor','prototype'].includes(part));
    const validDelimiter=(value:string|undefined)=>typeof value==='string'&&value.length>=1&&value.length<=8&&
      !/[\u0000-\u001f\u007f]/.test(value);
    if(rule.operator==='split_field'){
      const source=normalized[rule.source],targets=rule.targets??[];
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
      targets.forEach((target,i)=>{normalized[target]=parts[i]!;});continue;
    }
    if(rule.operator==='merge_fields'){
      const sources=rule.sources??[],target=rule.target.trim();
      if(!validDelimiter(rule.delimiter)||sources.length<2||sources.length>8||
         new Set(sources).size!==sources.length||!safeOutput(target)){
        error('normalize','ENRICHMENT_TARGET','Unsafe merge rule at step '+step);continue;
      }
      const values=sources.map(source=>normalized[source]);
      if(values.some(value=>typeof value!=='string')){
        error('normalize','ENRICHMENT_SOURCE','Merge sources must be existing string fields at step '+step);continue;
      }
      normalized[target]=(values as string[]).join(rule.delimiter!);continue;
    }
    const target = rule.target.trim();
    if (!safeOutput(target)) {
      error('normalize', 'ENRICHMENT_TARGET', 'Unsafe or duplicate enrichment output at step ' + step);
      continue;
    }
    if (rule.operator === 'set_const') {
      normalized[target] = rule.value;
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(normalized, rule.source)) {
      error('normalize', 'ENRICHMENT_SOURCE', 'Source field unavailable at step ' + step);
      continue;
    }
    const source = normalized[rule.source];
    if (rule.operator === 'copy') normalized[target] = source;
    else if (rule.operator === 'lowercase' || rule.operator === 'uppercase') {
      if (typeof source !== 'string') {
        error('normalize', 'ENRICHMENT_TYPE', 'Text transform requires a string source');
        continue;
      }
      normalized[target] = rule.operator === 'lowercase' ? source.toLowerCase() : source.toUpperCase();
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
    matched, extracted: matched, normalizedOk,
    status: hasErrors || !matched ? 'fail' : diagnostics.length ? 'warning' : 'pass',
    diagnostics, trace,
  };
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
