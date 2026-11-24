/**
 * Contract-driven strict key=value body parser.
 *
 * The pair expression, the separator, the trailing white space, the pair limit,
 * the forbidden keys and the escape set come from the code generated out of
 * contracts/syslog-header-grammar.v1.json (fragments.kv_pair). The generated
 * Ruby Fragment reads the same fragment, so both executors split pairs at the
 * same characters: SP and TAB separate pairs, every other character - NBSP and
 * U+2028 included - is value data.
 *
 * One exception, decided for the body as a whole: a body that is a delimited list - two or more pairs, each
 * separated from the next by the same list delimiter (, ; |) - is read as its pairs (fragments.kv_list_pair).
 * "src=10.0.0.1,dst=10.0.0.2" used to be one pair whose value was the rest of the line (Issue #315, Phase 3).
 */
import { GRAMMAR_FRAGMENTS, SYSLOG_HEADER_SEMANTICS, SYSLOG_HEADER_TOKENS } from './syslogHeaderGrammar.generated';

export type KvFailure = 'MALFORMED_PAIR' | 'FORBIDDEN_KEY' | 'DUPLICATE_KEY' | 'TOO_MANY_PAIRS' | 'NO_PAIRS';
export type KvBody =
  | { ok: true; pairs: Array<[key: string, value: string]> }
  | { ok: false; reason: KvFailure; key?: string };

import { matchAt, matchEnd } from './primitives';
import { sourceFieldName } from './sourceFieldNames';

const PAIR = new RegExp(GRAMMAR_FRAGMENTS.kv_pair.source, 'yu');
const LIST_PAIR = new RegExp(GRAMMAR_FRAGMENTS.kv_list_pair.source, 'yu');
const LIST_SEPARATOR = new RegExp(GRAMMAR_FRAGMENTS.kv_list_separator.source, 'yu');
const TRAILING = new RegExp('^(?:' + SYSLOG_HEADER_TOKENS.KV_TRAILING + ')$','u');
const UNESCAPED: readonly string[] = SYSLOG_HEADER_SEMANTICS.kvUnescapedAfterBackslash;

/**
 * Decodes a QUOTED value: only the escapes the contract lists; every other backslash (a Windows path) stays
 * as written. An unquoted value is never passed here (see parseStrictKeyValues).
 */
export function unescapeKvValue(raw: string): string {
  if (!raw.includes('\\')) return raw;
  let out = '';
  for (let index = 0; index < raw.length; index += 1) {
    const next = raw[index + 1];
    if (raw[index] === '\\' && next !== undefined) {
      out += UNESCAPED.includes(next) ? next : '\\' + next;
      index += 1;
    } else out += raw[index];
  }
  return out;
}

/**
 * True when the body is a delimited list: two or more list pairs, each separated from the next by the same
 * list delimiter, and only white space after the last one. One pair, pairs separated by white space, two
 * different delimiters, an empty item and a value the list grammar does not read (one with "=": a
 * distinguished name stays one value) are not a list, and the white space grammar reads the body.
 */
function isDelimitedPairList(input: string): boolean {
  let delimiter = '';
  let count = 0;
  let cursor = 0;
  while (cursor <= input.length) {
    const match = matchAt(LIST_PAIR, input, cursor);
    if (!match || matchEnd(match) <= cursor) return false;
    count += 1;
    // Past the pair limit the body is declined as a list (TOO_MANY_PAIRS); the rest is not read.
    if (count > SYSLOG_HEADER_SEMANTICS.kvMaxPairs) return true;
    cursor = matchEnd(match);
    if (TRAILING.test(input.slice(cursor))) return count >= 2;
    const separator = matchAt(LIST_SEPARATOR, input, cursor);
    if (!separator) return false;
    const found = separator.groups!.delimiter!;
    if (delimiter !== '' && found !== delimiter) return false;
    delimiter = found;
    cursor = matchEnd(separator);
  }
  return false;
}

export function parseStrictKeyValues(input: string): KvBody {
  const pairs: Array<[string, string]> = [];
  const seen = new Set<string>();
  const listed = isDelimitedPairList(input);
  let cursor = 0;
  while (cursor < input.length) {
    if (TRAILING.test(input.slice(cursor))) break;
    if (listed && pairs.length > 0) {
      const separator = matchAt(LIST_SEPARATOR, input, cursor);
      if (!separator) return { ok: false, reason: 'MALFORMED_PAIR' };
      cursor = matchEnd(separator);
    }
    const match = listed ? matchAt(LIST_PAIR, input, cursor) : matchAt(PAIR, input, cursor);
    if (!match || matchEnd(match) <= cursor) return { ok: false, reason: 'MALFORMED_PAIR' };
    // A name the JavaScript object model reserves is kept under its reversible field name (sourceFieldNames.ts, G-5).
    const key = sourceFieldName(match.groups!.key!);
    // Owner policy D-1: a repeated key is never resolved by keeping one of its values.
    if (seen.has(key)) return { ok: false, reason: 'DUPLICATE_KEY', key };
    if (pairs.length >= SYSLOG_HEADER_SEMANTICS.kvMaxPairs) return { ok: false, reason: 'TOO_MANY_PAIRS' };
    seen.add(key);
    // A quoted value needs an escape for its own quote, so it is decoded. An unquoted value has no quoting
    // syntax to escape from: it is the text as written, every backslash included. Decoding it turned the
    // share \\*\IPC$ of a Windows event into \*\IPC$ and reported the event as completely read.
    const quoted = match.groups!.dq ?? match.groups!.sq;
    const value = quoted === undefined ? (match.groups!.bare ?? '') : unescapeKvValue(quoted);
    // In a delimited list a quoted value is the text between its quotes (contract KV_LIST_DQ): nothing is decoded.
    pairs.push([key, listed && quoted !== undefined ? quoted : value]);
    cursor = matchEnd(match);
  }
  return pairs.length > 0 ? { ok: true, pairs } : { ok: false, reason: 'NO_PAIRS' };
}
