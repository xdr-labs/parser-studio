/**
 * Contract-driven strict key=value body parser.
 *
 * The pair expression, the separator, the trailing white space, the pair limit,
 * the forbidden keys and the escape set come from the code generated out of
 * contracts/syslog-header-grammar.v1.json (fragments.kv_pair). The generated
 * Ruby Fragment reads the same fragment, so both executors split pairs at the
 * same characters: SP and TAB separate pairs, every other character - NBSP and
 * U+2028 included - is value data.
 */
import { GRAMMAR_FRAGMENTS, SYSLOG_HEADER_SEMANTICS, SYSLOG_HEADER_TOKENS } from './syslogHeaderGrammar.generated';

export type KvFailure = 'MALFORMED_PAIR' | 'FORBIDDEN_KEY' | 'DUPLICATE_KEY' | 'TOO_MANY_PAIRS' | 'NO_PAIRS';
export type KvBody =
  | { ok: true; pairs: Array<[key: string, value: string]> }
  | { ok: false; reason: KvFailure; key?: string };

const PAIR = new RegExp(GRAMMAR_FRAGMENTS.kv_pair.source, 'y');
const TRAILING = new RegExp('^(?:' + SYSLOG_HEADER_TOKENS.KV_TRAILING + ')$');
const UNESCAPED: readonly string[] = SYSLOG_HEADER_SEMANTICS.kvUnescapedAfterBackslash;
const FORBIDDEN: readonly string[] = SYSLOG_HEADER_SEMANTICS.kvForbiddenKeys;

/** Only the escapes the contract lists are decoded; every other backslash (a Windows path) stays as written. */
export function unescapeKvValue(raw: string): string {
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

export function parseStrictKeyValues(input: string): KvBody {
  const pairs: Array<[string, string]> = [];
  const seen = new Set<string>();
  let cursor = 0;
  while (cursor < input.length) {
    if (TRAILING.test(input.slice(cursor))) break;
    PAIR.lastIndex = cursor;
    const match = PAIR.exec(input);
    if (!match || match.index !== cursor || PAIR.lastIndex <= cursor) return { ok: false, reason: 'MALFORMED_PAIR' };
    const key = match.groups!.key!;
    if (FORBIDDEN.includes(key)) return { ok: false, reason: 'FORBIDDEN_KEY', key };
    // Owner policy D-1: a repeated key is never resolved by keeping one of its values.
    if (seen.has(key)) return { ok: false, reason: 'DUPLICATE_KEY', key };
    if (pairs.length >= SYSLOG_HEADER_SEMANTICS.kvMaxPairs) return { ok: false, reason: 'TOO_MANY_PAIRS' };
    seen.add(key);
    pairs.push([key, unescapeKvValue(match.groups!.dq ?? match.groups!.sq ?? match.groups!.bare ?? '')]);
    cursor = PAIR.lastIndex;
  }
  return pairs.length > 0 ? { ok: true, pairs } : { ok: false, reason: 'NO_PAIRS' };
}
