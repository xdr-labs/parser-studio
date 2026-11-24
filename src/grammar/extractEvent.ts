/**
 * The one extraction entry of every supported format.
 *
 * extractEvent reads one event with the extraction settings of a parser project and returns its fields or the
 * reason it is declined. The browser preview executes it as written; the generated Ruby parser executes its
 * translation (scripts/grammar/ts2rb, backend/templates/grammar-core.generated.rb.tpl). There is no second
 * implementation of a format, of the mixed router or of the CSV tokenizer to keep in step.
 *
 * Only a Regex extraction is not expressed here: the pattern is the user's, it is executed by the regular
 * expression engine of each runtime (extractPortableRegexFields in the browser, the cost-proven native
 * expression in Ruby) and compared by the differential gate.
 */
import { extractGenericStructural, type GenericStructuralProfile } from '../genericStructural';
import type { ForwarderConfig } from '../guided/declaredForwarder';
import { parseJavaStacktrace } from '../javaStacktrace';
import { hasDuplicateJsonObjectKeys } from '../jsonDuplicateKeys';
import { hasUnsafeJsonNumbers } from '../jsonNumberSafety';
import { jsonSourceValueValid } from '../jsonSourceSafety';
import { extractPortableRegexFields } from '../portableRegexExtraction';
import { extractStructuredFamily, strictKeyValues, type StructuredExtraction, extractStandaloneFamily } from '../structuredFamilies';
import { setTag } from './primitives';
import { matchRfc3164Header } from './syslogHeader';
import { SYSLOG_HEADER_TOKENS } from './syslogHeaderGrammar.generated';
import { withSourceFieldNames } from './sourceFieldNames';

/** The `extraction` object of a compiled parser project (backend/src/types.ts), as far as the grammar reads it. */
export interface ExtractionSettings {
  format: string;
  pattern?: string;
  mixedFormats?: readonly string[];
  csvColumns?: readonly string[];
  csvDelimiter?: string;
  /** 'auto' is the browser's format detection for a Syslog body; a compiled project never carries it. */
  syslogBodyFormat?: 'raw' | 'json' | 'kv' | 'cef' | 'leef' | 'regex' | 'auto';
  genericStructuralProfile?: GenericStructuralProfile;
  genericStructuralFamilyGrammar?: 'dedicated';
  /** Declared Syslog relays whose envelope is removed before the event is read (src/guided/declaredForwarder.ts). */
  forwarder?: ForwarderConfig;
}

const failure = (message: string): StructuredExtraction => ({ fields: {}, errors: [message] });

export function extractJsonObject(raw: string): StructuredExtraction {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') return failure('JSON event must be an object');
    if (hasDuplicateJsonObjectKeys(raw)) return failure('Duplicate JSON object key: review the source before generating a parser');
    if (hasUnsafeJsonNumbers(raw)) return failure('Unsafe JSON numeric precision: quote large integer identifiers as strings before mapping');
    if (!jsonSourceValueValid(parsed)) return failure('JSON source exceeds the native nesting limit or has an invalid Unicode surrogate');
    // Member names the JavaScript object model reserves are kept under their reversible field names (G-5).
    const result: StructuredExtraction = { fields: withSourceFieldNames(parsed) as Record<string, unknown>, errors: [] };
    setTag(result, 'bodyKind', 'json');
    return result;
  } catch {
    return failure('Invalid JSON object');
  }
}

const CSV_DELIMITERS: readonly string[] = [',', ';', '\t'];
/**
 * An unquoted cell without the SP and TAB at its edges. Written as two scans from the ends: the expression
 * `^[ \t]+|[ \t]+$` was tried at every blank of a long run inside a cell (a=1, eight thousand spaces, b=2)
 * and held the generated parser for half a second on one event of the default size (audit of 2026-11-15).
 */
function withoutEdgeBlanks(token: string): string {
  let start = 0;
  let end = token.length;
  while (start < end && (token[start] === ' ' || token[start] === '\t')) start += 1;
  while (end > start && (token[end - 1] === ' ' || token[end - 1] === '\t')) end -= 1;
  return start === 0 && end === token.length ? token : token.slice(start, end);
}
const CSV_COLUMN_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/u;

/**
 * The cells of one RFC 4180 row; null for a row that is not one. An empty unquoted cell is null (a missing
 * value), an empty quoted cell is the empty string. With `,` and `;` the SP and TAB at the edges of an unquoted
 * cell are not data; with TAB as the delimiter every character of a cell is.
 */
export function tokenizeCsvRow(raw: string, delimiter: string): (string | null)[] | null {
  if (!CSV_DELIMITERS.includes(delimiter)) return null;
  const out: (string | null)[] = [];
  const stripUnquoted = delimiter !== '\t';
  // A cell is cut out of the row in one piece (a quoted cell in the pieces between its doubled marks): adding
  // one character at a time copied the cell once per character in the generated parser.
  let token = '';
  let from = 0;
  let state: 'start' | 'plain' | 'quoted' | 'afterQuote' = 'start';
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]!;
    if (state === 'quoted') {
      if (c === '"') {
        token += raw.slice(from, i);
        if (raw[i + 1] === '"') { token += '"'; i++; from = i + 1; }
        else state = 'afterQuote';
      }
    } else if (state === 'afterQuote') {
      if (c === delimiter) { out.push(token); token = ''; state = 'start'; }
      else if (stripUnquoted && (c === ' ' || c === '\t')) continue;
      else return null;
    } else if (c === delimiter) {
      out.push(state === 'start' ? null : stripUnquoted ? withoutEdgeBlanks(raw.slice(from, i)) : raw.slice(from, i));
      token = ''; state = 'start';
    } else if (c === '"') {
      if (state !== 'start') return null;
      state = 'quoted';
      from = i + 1;
    } else if (state === 'start' && stripUnquoted && (c === ' ' || c === '\t')) {
      // White space next to a field is not data, but a quotation mark inside a started unquoted value is
      // still not a field.
      continue;
    } else {
      if (state === 'start') from = i;
      state = 'plain';
    }
  }
  if (state === 'quoted') return null;
  out.push(state === 'start' ? null : state === 'afterQuote' ? token : stripUnquoted ? withoutEdgeBlanks(raw.slice(from)) : raw.slice(from));
  // A row that is empty (or, where field edges are stripped, only spaces and TABs) is no row.
  if (out.length === 1 && out[0] === null) return null;
  return out;
}

export function extractCsvRow(raw: string, columns: readonly string[], delimiter: string): StructuredExtraction {
  if (!CSV_DELIMITERS.includes(delimiter)) return failure('Unsupported CSV data delimiter');
  if (!columns.length || columns.length > 100 || columns.some(name => !CSV_COLUMN_NAME.test(name)) ||
      new Set(columns).size !== columns.length) return failure('Provide unique valid CSV column names');
  const values = tokenizeCsvRow(raw, delimiter);
  if (!values) return failure('Malformed CSV quotation or unsupported delimiter');
  if (values.length !== columns.length)
    return failure('CSV column count mismatch: expected ' + columns.length + ', received ' + values.length);
  const fields: Record<string, unknown> = {};
  for (let index = 0; index < columns.length; index++) fields[columns[index]!] = values[index];
  const result: StructuredExtraction = { fields, errors: [] };
  setTag(result, 'bodyKind', 'csv');
  return result;
}

const MIXED_FAMILIES: readonly string[] = ['json', 'kv', 'cef', 'leef', 'rfc5424_cef', 'rfc5424_leef', 'rfc3164_kv', 'rfc5424_json', 'rfc5424_kv', 'rfc3164_cef', 'rfc3164_leef', 'csv'];
const BSD_ENVELOPE = new RegExp('^(?:<\\d{1,3}>)?' + SYSLOG_HEADER_TOKENS.BSD_MONTH + ' +\\d{1,2} +\\d{2}:', 'u');
const KEY_VALUE_START = /^[A-Za-z_][A-Za-z0-9_.-]*=/u;

/**
 * The family the mixed router read an event with, on the extraction and out of band (a tag, never a field):
 * the reading itself, not a value of the event. Conditional event-family normalization can route on it
 * (eventProfiles discriminator `@reading_family`); no field of the event can claim it.
 */
function mixedFamily(result: StructuredExtraction, family: string): StructuredExtraction {
  if (result.errors.length === 0) setTag(result, 'mixedFamily', family);
  return result;
}

/**
 * The mixed router. The family of a line is decided by its exact prefix, and the family of a Syslog envelope by
 * the exact prefix of its message: nothing is trimmed and no body parser is tried on spec. A BSD timestamp
 * opens an RFC 3164 envelope with or without PRI. A broken header never falls back to key=value.
 */
export function extractMixed(raw: string, settings: ExtractionSettings): StructuredExtraction {
  const selected = settings.mixedFormats ?? [];
  if (selected.length < 2 || selected.length > 4 || new Set(selected).size !== selected.length ||
      selected.some(family => !MIXED_FAMILIES.includes(family)))
    return failure('Select an explicit bounded mixed-family allowlist');
  const bsdEnvelope = BSD_ENVELOPE.test(raw);
  if (!raw.startsWith('{') && !raw.startsWith('CEF:') && !raw.startsWith('LEEF:') && (bsdEnvelope || raw.startsWith('<'))) {
    const grammar = bsdEnvelope ? 'syslog_rfc3164' : 'syslog_rfc5424';
    // The message of the envelope, from the header grammar alone (a tagless RFC 3164 line has one too).
    let message: unknown;
    if (bsdEnvelope) {
      const header = matchRfc3164Header(raw);
      message = header.ok ? header.message : undefined;
    } else {
      const header = extractStructuredFamily(raw, grammar, 'raw');
      message = header.errors.length ? undefined : header.fields.message;
    }
    const body = typeof message !== 'string' ? null :
      message.startsWith('CEF:') ? 'cef' as const :
      message.startsWith('LEEF:') ? 'leef' as const :
      !bsdEnvelope && message.startsWith('{') ? 'json' as const :
      KEY_VALUE_START.test(message) ? 'kv' as const : null;
    const mode = body ? (bsdEnvelope ? 'rfc3164' : 'rfc5424') + '_' + body : null;
    if (!body || !mode || !selected.includes(mode))
      return failure(bsdEnvelope ? 'RFC3164 TAG body is unsupported or not allowlisted' : 'Wrapped Syslog is malformed or not in mixed allowlist');
    return mixedFamily(extractStructuredFamily(raw, grammar, body), mode);
  }
  const columns = settings.csvColumns ?? [];
  const delimiter = settings.csvDelimiter ?? ',';
  const family =
    raw.startsWith('{') ? 'json' :
    raw.startsWith('CEF:') ? 'cef' :
    raw.startsWith('LEEF:') ? 'leef' :
    KEY_VALUE_START.test(raw) ? 'kv' :
    // CSV is a family only with a reviewed schema of at least two columns.
    selected.includes('csv') && columns.length >= 2 && raw.includes(delimiter) ? 'csv' : null;
  if (!family || !selected.includes(family)) return failure('Mixed event is unsupported or excluded by allowlist');
  if (family === 'kv') return mixedFamily(strictKeyValues(raw), family);
  if (family === 'csv') return mixedFamily(extractCsvRow(raw, columns, delimiter), family);
  if (family === 'json') return mixedFamily(extractJsonObject(raw), family);
  return mixedFamily(extractStructuredFamily(raw, family), family);
}

export function extractEvent(raw: string, settings: ExtractionSettings): StructuredExtraction {
  const format = settings.format;
  if (format === 'json') return extractJsonObject(raw);
  if (format === 'kv') return strictKeyValues(raw);
  if (format === 'csv') return extractCsvRow(raw, settings.csvColumns ?? [], settings.csvDelimiter ?? ',');
  if (format === 'java_stacktrace') return parseJavaStacktrace(raw);
  if (format === 'generic_structural')
    return extractGenericStructural(raw, settings.genericStructuralProfile, settings.genericStructuralFamilyGrammar);
  if (format === 'mixed') return extractMixed(raw, settings);
  if (format === 'syslog_rfc3164' || format === 'syslog_rfc5424')
    return extractStructuredFamily(raw, format, settings.syslogBodyFormat ?? 'raw', settings.pattern);
  if (format === 'cef' || format === 'leef') return extractStandaloneFamily(raw, format);
  if (format === 'regex') return extractPortableRegexFields(raw, settings.pattern ?? '');
  return failure('Unsupported extraction format');
}
