/**
 * Loss accounting for CSV, JSON, CEF and LEEF (Parsing Success Contract).
 *
 * An extractor that returns no error has not thereby kept everything: a tokenizer that drops a cell, truncates
 * a value or skips a member still "succeeds". Each function here reads the ORIGINAL text of the event a second
 * time, with code that shares nothing with the extractor (no regular expression, no splitter, no decoder of
 * the extractor is used), and answers one question: do the extracted fields spell that text, all of it and
 * nothing else? null means yes; otherwise the answer is the reason, and the event is PARTIAL, never FULL.
 *
 * The reasons never contain event text (raw logs are sensitive).
 *
 * The functions are part of the shared grammar: the browser preview and the generated Ruby parser execute
 * the same code (scripts/grammar/ts2rb), so an event is graded identically in both.
 */
import { SYSLOG_HEADER_SEMANTICS, SYSLOG_HEADER_TOKENS } from './syslogHeaderGrammar.generated';
import { originalFieldName, sourceFieldName } from './sourceFieldNames';

/**
 * CSV by reconstruction: the cells, written back in the only ways RFC 4180 writes them, must spell the row.
 * An unquoted cell is its own text, a quoted cell is the text between quotation marks with each mark doubled,
 * and with `,` or `;` the SP and TAB next to a cell are not data.
 */
export function csvRowUnaccounted(text: string, delimiter: string, cells: readonly unknown[]): string | null {
  return rowUnaccounted(text, delimiter, cells, delimiter !== '\t');
}

/**
 * The positional CSV of Generic Structural: comma-separated cells in which every character of an unquoted cell
 * is data (no SP or TAB is set aside) and an empty cell is the empty string.
 */
export function positionalCsvUnaccounted(text: string, cells: readonly unknown[]): string | null {
  return rowUnaccounted(text, ',', cells, false);
}

function rowUnaccounted(text: string, delimiter: string, cells: readonly unknown[], strip: boolean): string | null {
  let cursor = 0;
  for (let index = 0; index < cells.length; index++) {
    if (strip) while (text[cursor] === ' ' || text[cursor] === '\t') cursor++;
    const cell = cells[index];
    if (typeof cell === 'string') {
      const written = text[cursor] === '"' ? '"' + cell.split('"').join('""') + '"' : cell;
      if (!text.startsWith(written, cursor)) return 'CSV cell ' + (index + 1) + ' is not the text of the row at its position';
      cursor += written.length;
    } else if (cell !== null) return 'CSV cell ' + (index + 1) + ' is not text';
    if (strip) while (text[cursor] === ' ' || text[cursor] === '\t') cursor++;
    if (index < cells.length - 1) {
      if (text[cursor] !== delimiter) return 'the row has no delimiter after CSV cell ' + (index + 1);
      cursor++;
    }
  }
  return cursor === text.length ? null : 'text after the last CSV cell is not part of any cell';
}

const JSON_ESCAPES: Readonly<Record<string, string>> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
const JSON_NUMBER_START = '-0123456789';
const JSON_NUMBER_UNITS = '0123456789eE+-.';

function bump(counts: Map<string, number>, token: string, delta: number): void {
  counts.set(token, (counts.get(token) ?? 0) + delta);
}

/** The scalar tokens of JSON text, counted: every member name and string, number and literal. */
function countJsonTextTokens(text: string, counts: Map<string, number>): boolean {
  const length = text.length;
  // Four hexadecimal digits read unit by unit (never a window cut out of the text).
  const hex = (at: number): number => parseInt((text[at] ?? '') + (text[at + 1] ?? '') + (text[at + 2] ?? '') + (text[at + 3] ?? ''), 16);
  let index = 0;
  while (index < length) {
    const char = text[index]!;
    if (char === '"') {
      let value = '';
      index++;
      for (;;) {
        if (index >= length) return false;
        const unit = text[index]!;
        if (unit === '"') { index++; break; }
        if (unit !== '\\') { value += unit; index++; continue; }
        const escape = text[index + 1] ?? '';
        if (escape !== 'u') {
          if (!Object.prototype.hasOwnProperty.call(JSON_ESCAPES, escape)) return false;
          value += JSON_ESCAPES[escape]!;
          index += 2;
          continue;
        }
        const code = hex(index + 2);
        if (code >= 0xd800 && code <= 0xdbff && text[index + 6] === '\\' && text[index + 7] === 'u') {
          const low = hex(index + 8);
          if (!(low >= 0xdc00 && low <= 0xdfff)) return false;
          value += String.fromCodePoint(0x10000 + (code - 0xd800) * 0x400 + (low - 0xdc00));
          index += 12;
        } else {
          if (!(code >= 0) || (code >= 0xd800 && code <= 0xdfff)) return false;
          value += String.fromCodePoint(code);
          index += 6;
        }
      }
      bump(counts, 's:' + value, 1);
    } else if (JSON_NUMBER_START.includes(char)) {
      let digits = char;
      index++;
      while (index < length && JSON_NUMBER_UNITS.includes(text[index]!)) { digits += text[index]!; index++; }
      bump(counts, 'n:' + String(Number(digits)), 1);
    } else if (char === 't' || char === 'f' || char === 'n') {
      const literal = char === 't' ? 'true' : char === 'f' ? 'false' : 'null';
      bump(counts, 'l:' + literal, 1);
      index += literal.length;
    } else index++;
  }
  return true;
}

function countJsonValueTokens(value: unknown, counts: Map<string, number>): void {
  if (Array.isArray(value)) { for (const item of value) countJsonValueTokens(item, counts); return; }
  if (value !== null && typeof value === 'object') {
    // A field name stands for the member name of the text (sourceFieldNames.ts, G-5).
    for (const [name, item] of Object.entries(value)) { bump(counts, 's:' + originalFieldName(name), -1); countJsonValueTokens(item, counts); }
    return;
  }
  if (typeof value === 'string') bump(counts, 's:' + value, -1);
  else if (typeof value === 'number') bump(counts, 'n:' + String(value), -1);
  else bump(counts, 'l:' + String(value), -1);
}

/**
 * JSON by token count: the member names, strings, numbers and literals of the text, read by a scanner of its
 * own, are exactly those of the extracted fields (member order is not part of JSON and is not compared).
 */
export function jsonTextUnaccounted(text: string, fields: unknown): string | null {
  const counts = new Map<string, number>();
  if (!countJsonTextTokens(text, counts)) return 'the JSON text could not be read a second time';
  countJsonValueTokens(fields, counts);
  for (const [_token, count] of counts) {
    if (count > 0) return 'a name or value of the JSON text is missing from the extracted fields';
    if (count < 0) return 'an extracted field holds a name or value that is not in the JSON text';
  }
  return null;
}

interface HeaderField { value: string; next: number }

/** The header field that starts at `from`: its value (`\|` and `\\` are the bar and the backslash) and the position after its `|`. */
function headerFieldAt(text: string, from: number): HeaderField | null {
  let value = '';
  let at = from;
  for (;;) {
    const unit = text[at];
    if (unit === undefined) return null;
    if (unit === '|') return { value, next: at + 1 };
    if (unit !== '\\') { value += unit; at++; continue; }
    const escaped = text[at + 1];
    if (escaped === undefined) return null;
    value += escaped === '|' || escaped === '\\' ? escaped : '\\' + escaped;
    at += 2;
  }
}

/** The position after the header when the header fields spell it (`<prefix><version>|field|field|...|`), or -1. */
function headerEnd(text: string, prefix: string, names: readonly string[], fields: Record<string, unknown>): number {
  const version = fields[names[0]!];
  if (typeof version !== 'string') return -1;
  // A CEF header may have one space after "CEF:" (the FortiGate form, see structuredFamilies.ts).
  const lead = text.startsWith(prefix + version + '|') ? prefix :
    prefix === 'CEF:' && text.startsWith(prefix + ' ' + version + '|') ? prefix + ' ' : null;
  if (lead === null) return -1;
  let cursor = lead.length + version.length + 1;
  for (let index = 1; index < names.length; index++) {
    const field = headerFieldAt(text, cursor);
    if (field === null || fields[names[index]!] !== field.value) return -1;
    cursor = field.next;
  }
  return cursor;
}

const CEF_HEADER_FIELDS: readonly string[] = ['cef_version', 'cef_device_vendor', 'cef_device_product', 'cef_device_version', 'cef_signature_id', 'cef_name', 'cef_severity'];
const LEEF_HEADER_FIELDS: readonly string[] = ['leef_version', 'leef_vendor', 'leef_product', 'leef_product_version', 'leef_event_id'];
const CEF_ESCAPES: Readonly<Record<string, string>> = SYSLOG_HEADER_SEMANTICS.cefExtensionEscapes;
const CEF_BLANK = ' \t\n\v\f\r\0';
// Where a pair starts inside extension text: white space, a key, `=`. What a key looks like is the one thing
// taken from the contract; where the extractor decided that a value ends is not used.
const CEF_PAIR_START = new RegExp('[ \\t]' + SYSLOG_HEADER_TOKENS.CEF_KEY + '=', 'u');
const LEEF_DELIMITER_VERSIONS: readonly string[] = SYSLOG_HEADER_SEMANTICS.leefDelimiterFieldVersions;

/**
 * CEF by reconstruction: the header fields spell the header, and the extension is, from its first character
 * to its last, `key=value` pairs separated by SP or TAB in which every key is a field and every value, with
 * the escapes of the contract (contracts/syslog-header-grammar.v1.json) read on the way, is that field's value.
 */
export function cefEventUnaccounted(text: string, fields: Record<string, unknown>): string | null {
  let cursor = headerEnd(text, 'CEF:', CEF_HEADER_FIELDS, fields);
  if (cursor < 0) return 'a CEF header field is not the text of the event';
  const length = text.length;
  let blank = cursor;
  while (blank < length && CEF_BLANK.includes(text[blank]!)) blank++;
  let seen = 0;
  while (blank < length) {
    while (cursor < length && (text[cursor] === ' ' || text[cursor] === '\t')) cursor++;
    if (cursor >= length) break;
    let key = '';
    while (cursor < length && text[cursor] !== '=' && text[cursor] !== ' ' && text[cursor] !== '\t') { key += text[cursor]!; cursor++; }
    if (text[cursor] !== '=') return 'text of the CEF extension is not part of any extracted field';
    cursor++;
    const value = CEF_HEADER_FIELDS.includes(key) ? undefined : fields[sourceFieldName(key)];
    if (typeof value !== 'string') return 'a key=value pair of the CEF extension is missing from the extracted fields';
    let index = 0;
    const valueStart = cursor;
    while (index < value.length) {
      const unit = text[cursor];
      if (unit === undefined) return 'an extracted CEF value is not the text of its key=value pair';
      if (unit !== '\\') {
        if (value[index] !== unit) return 'an extracted CEF value is not the text of its key=value pair';
        index++;
        cursor++;
        continue;
      }
      const escaped = text[cursor + 1];
      if (escaped === undefined) return 'an extracted CEF value is not the text of its key=value pair';
      // A backslash before SP or TAB takes nothing with it: it is one character of the value.
      if (escaped === ' ' || escaped === '\t') {
        if (value[index] !== '\\') return 'an extracted CEF value is not the text of its key=value pair';
        index++;
        cursor++;
        continue;
      }
      if (Object.prototype.hasOwnProperty.call(CEF_ESCAPES, escaped)) {
        if (value[index] !== CEF_ESCAPES[escaped]) return 'an extracted CEF value is not the text of its key=value pair';
        index++;
      } else {
        if (value[index] !== '\\' || value[index + 1] !== escaped) return 'an extracted CEF value is not the text of its key=value pair';
        index += 2;
      }
      cursor += 2;
    }
    seen++;
    if (cursor < length && text[cursor] !== ' ' && text[cursor] !== '\t') return 'an extracted CEF value ends before the text of its value does';
    // The walk above follows the extracted value, so it cannot see a value that ran into the next pair. A pair
    // that starts inside the text of a value is one (`filePath=C:\\Users\\bob\\ suser=bob` read as one value).
    if (CEF_PAIR_START.test(text.slice(valueStart, cursor))) return 'a key=value pair of the CEF extension is inside an extracted value';
  }
  return Object.keys(fields).length === CEF_HEADER_FIELDS.length + seen ? null : 'an extracted field is not in the CEF extension';
}

/**
 * LEEF by reconstruction: the header fields spell the header, and the extension is `key=value` attributes
 * joined by the delimiter of the event (TAB, or the one the delimiter field declares as a character or in
 * hexadecimal) in which every key is a field and every value is, character for character, that field's value.
 */
export function leefEventUnaccounted(text: string, fields: Record<string, unknown>): string | null {
  let cursor = headerEnd(text, 'LEEF:', LEEF_HEADER_FIELDS, fields);
  if (cursor < 0) return 'a LEEF header field is not the text of the event';
  let delimiter: string = SYSLOG_HEADER_SEMANTICS.leefDefaultDelimiter;
  if (LEEF_DELIMITER_VERSIONS.includes(String(fields.leef_version))) {
    const declared = headerFieldAt(text, cursor);
    if (declared === null) return 'the LEEF delimiter field is incomplete';
    cursor = declared.next;
    const spelled = declared.value;
    if (spelled.length === 1) delimiter = spelled;
    else {
      const code = parseInt(spelled.startsWith('0x') ? spelled.slice(2) : spelled.slice(1), 16);
      if (!(code >= 0)) return 'the LEEF delimiter field does not declare a delimiter';
      delimiter = String.fromCharCode(code);
    }
  }
  const length = text.length;
  let seen = 0;
  while (cursor < length) {
    let key = '';
    while (cursor < length && text[cursor] !== '=' && text[cursor] !== delimiter) { key += text[cursor]!; cursor++; }
    if (text[cursor] !== '=') return 'text of the LEEF extension is not part of any extracted attribute';
    cursor++;
    const value = LEEF_HEADER_FIELDS.includes(key) ? undefined : fields[sourceFieldName(key)];
    if (typeof value !== 'string') return 'an attribute of the LEEF extension is missing from the extracted fields';
    if (!text.startsWith(value, cursor)) return 'an extracted LEEF value is not the text of its attribute';
    cursor += value.length;
    seen++;
    if (cursor === length) break;
    if (text[cursor] !== delimiter) return 'an extracted LEEF value ends before the text of its value does';
    cursor++;
    if (cursor === length) return 'text of the LEEF extension is not part of any extracted attribute';
  }
  return Object.keys(fields).length === LEEF_HEADER_FIELDS.length + seen ? null : 'an extracted field is not in the LEEF extension';
}
