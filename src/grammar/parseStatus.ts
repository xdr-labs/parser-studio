/**
 * Parsing Success Contract.
 *
 *   FULL     every verifiable field and the event boundary are correct
 *   PARTIAL  some field or span was not recovered; the original text is kept
 *   UNKNOWN  the structure cannot be trusted, so nothing is auto-parsed
 *   ERROR    an execution failure or a contract violation
 *
 * A parser result alone cannot prove FULL: a grammar that swallows a field into
 * the wrong place still "succeeds". This module therefore re-reads the ORIGINAL
 * line with a deliberately separate, much simpler tokenizer and refuses FULL
 * when a key=value pair that is visible in the raw text is not present, with the
 * same value, in the extracted fields. FULL does not require a Stellar mapping
 * for every vendor field; it is about extraction, not mapping.
 */
export type ParseStatus = 'FULL' | 'PARTIAL' | 'UNKNOWN' | 'ERROR';

import { getTag, matchAt, matchEnd } from './primitives';

export interface StructuredOutcome { fields: Record<string, unknown>; errors: string[] }
export interface RawPair { key: string; value: string; rawValue: string; quoted: boolean }
export interface ParseVerdict { status: ParseStatus; lostPairs: RawPair[]; reasons: string[] }

// Sticky: tried exactly where a token starts, without cutting a window out of the text.
const KEY_AT_TOKEN_START = /[A-Za-z_][A-Za-z0-9_.-]{0,95}=/uy;
// Tokens are separated by ASCII white space (SP, TAB, LF, VT, FF, CR): the key=value grammar never puts one of
// these into an unquoted value and allows them after the last pair (contract KV_BARE, KV_TRAILING), so a form
// feed at the end of the line is not part of the last value. Each run is taken in one step: reading the line
// character by character cost the generated parser more than the key=value grammar itself (measured on Ruby
// 2.4.9, 2026-11-15).
const GAP_RUN = /[ \t\n\x0b\f\r]*/uy;
const TOKEN_RUN = /[^ \t\n\x0b\f\r]*/uy;
const BACKSLASH_PAIR = /\\./gsu;
// List delimiters. The key=value grammar never separates pairs at one of them (contract KV_GAP: SP and TAB), and
// that is the reason this reader must: "a=1,b=2" is two pairs whatever the grammar made of the line. A reader
// that cut tokens at white space only shared the grammar's assumption and could not see the second pair, so a
// line whose pairs are separated by commas alone was reported FULL with one field (Issue #315, Phase 3).
// Compared character by character: in the generated Ruby a string search for a character beyond ASCII raises
// when the artifact was loaded as US-ASCII source, a comparison is simply false.
function isListDelimiter(ch: string): boolean {
  return ch === ',' || ch === ';' || ch === '|';
}

/**
 * RFC 5424 section 6: after "<PRI>VERSION" come five header fields, each separated by exactly one SP and
 * each defined by its position alone. A HOSTNAME written "a=b" is a host name, not a pair, so pair
 * accounting starts after the sixth token. An RFC 3164 header gets no such exemption: its HOSTNAME is
 * optional, which is exactly how a first key=value pair was once lost into it (F-1).
 */
function positionalHeaderEnd(raw: string): number {
  if (!/^<[0-9]{1,3}>[0-9]{1,3} /u.test(raw)) return 0;
  let index = 0;
  for (let token = 0; token < 6; token += 1) {
    const space = raw.indexOf(' ', index);
    if (space < 0) return raw.length;
    index = space + 1;
  }
  return structuredDataEnd(raw, index);
}

/**
 * RFC 5424 section 6.3: STRUCTURED-DATA follows the header, as NILVALUE or as SD-ELEMENTs. An SD-PARAM is
 * written NAME="value" but it is not a key=value pair of the MSG: the extractor stores it under its
 * SD-ELEMENT (and encodes a name that is not a plain identifier), so pair accounting starts after it
 * (PR #311 review). Text that is not well-formed STRUCTURED-DATA is not skipped: the index is returned
 * unchanged and every pair in it is accounted for.
 */
function structuredDataEnd(raw: string, start: number): number {
  const after = (index: number) => (index === raw.length ? index : raw[index] === ' ' ? index + 1 : -1);
  if (raw[start] === '-') { const end = after(start + 1); return end < 0 ? start : end; }
  let index = start;
  while (raw[index] === '[') {
    let cursor = index + 1;
    let quoted = false;
    for (; cursor < raw.length; cursor += 1) {
      const ch = raw[cursor];
      if (quoted && ch === '\\') { cursor += 1; continue; }
      if (ch === '"') { quoted = !quoted; continue; }
      if (ch === ']' && !quoted) break;
    }
    if (cursor >= raw.length) return start;
    index = cursor + 1;
  }
  if (index === start) return start;
  const end = after(index);
  return end < 0 ? start : end;
}

/**
 * Offset of the quote that closes a quoted value whose body starts at `from`, or -1. A backslash takes the
 * next character with it, so a quote after an odd run of backslashes belongs to the value. Stated on the
 * positions of the quote character, not as a pattern of the body: this reader is not the product grammar.
 */
function closingQuote(raw: string, quote: string, from: number): number {
  let at = raw.indexOf(quote, from);
  while (at >= 0) {
    let run = 0;
    while (at - 1 - run >= from && raw[at - 1 - run] === '\\') run += 1;
    if (run % 2 === 0) return at;
    at = raw.indexOf(quote, at + 1);
  }
  return -1;
}

/** True when the key of a pair starts at `at` and its "=" lies before `end`. */
function keyStartsAt(raw: string, at: number, end: number): boolean {
  const key = matchAt(KEY_AT_TOKEN_START, raw, at);
  return key !== null && matchEnd(key) <= end;
}

/**
 * Where the unquoted value of the token [from, end) stops: at a list delimiter that the key of another pair
 * follows, either inside the token ("1,b=2") or as its last character when the next token is a pair
 * ("1, b=2"). A value that holds "=" before such a delimiter is a list of its own - a distinguished name
 * "CN=a,OU=b", a cookie, a query string - and stays whole, as does a delimiter that no key follows ("a,b,c").
 */
function unquotedValueEnd(raw: string, from: number, end: number): number {
  for (let at = from; at < end; at += 1) {
    const ch = raw[at]!;
    if (ch === '=') return end;
    if (!isListDelimiter(ch)) continue;
    const next = at + 1 < end ? at + 1 : matchEnd(matchAt(GAP_RUN, raw, end)!);
    if (keyStartsAt(raw, next, at + 1 < end ? end : raw.length)) return at;
  }
  return end;
}

/**
 * Independent evidence: key=value pairs that start a whitespace-separated token
 * of the raw line, or that follow a list delimiter (, ; |) inside such a token. Values in double or single
 * quotes are consumed whole, so a '=' inside a quoted value is never reported as a pair of its own. This is
 * intentionally not the product KV parser.
 */
export function independentKeyValuePairs(raw: string): RawPair[] {
  const pairs: RawPair[] = [];
  const length = raw.length;
  let index = positionalHeaderEnd(raw);
  while (index < length) {
    index = matchEnd(matchAt(GAP_RUN, raw, index)!);
    if (index >= length) break;
    const key = matchAt(KEY_AT_TOKEN_START, raw, index);
    if (key) {
      index += key[0].length;
      const quote = raw[index];
      if (quote === '"' || quote === "'") {
        // Without a closing quote (the text ends, or ends in a backslash) the token is read as an unquoted
        // value below.
        const cursor = closingQuote(raw, quote, index + 1);
        if (cursor >= 0) {
          const rawValue = raw.slice(index + 1, cursor);
          const value = rawValue.includes('\\') ? rawValue.replace(BACKSLASH_PAIR, pair => pair.slice(1)) : rawValue;
          pairs.push({ key: key[0].slice(0, -1), value, rawValue, quoted: true });
          index = cursor + 1;
          // A list delimiter between the closing quote and the next key separates two pairs.
          if (index < length && isListDelimiter(raw[index]!) &&
            keyStartsAt(raw, matchEnd(matchAt(GAP_RUN, raw, index + 1)!), length)) index += 1;
          continue;
        }
      }
      // An unquoted value ends at white space, or at a list delimiter that another pair follows. No backslash
      // rule here: this reader must not share the grammar's idea of an escape (a backslash that carried the
      // next SP made the grammar swallow the following pair, and a reader with the same rule could not see it).
      const end = matchEnd(matchAt(TOKEN_RUN, raw, index)!);
      const stop = unquotedValueEnd(raw, index, end);
      const value = raw.slice(index, stop);
      pairs.push({ key: key[0].slice(0, -1), value, rawValue: value, quoted: false });
      index = stop < end ? stop + 1 : end;
      continue;
    }
    index = matchEnd(matchAt(TOKEN_RUN, raw, index)!);
  }
  return pairs;
}

function collectLeaves(value: unknown, key: string, out: Map<string, string[]>): void {
  // The values of a list belong to the field that holds the list.
  if (Array.isArray(value)) { for (const child of value) collectLeaves(child, key, out); return; }
  if (value !== null && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) collectLeaves(child, childKey, out);
    return;
  }
  if (value === undefined || value === null) return;
  const list = out.get(key);
  if (list) list.push(String(value)); else out.set(key, [String(value)]);
}

/**
 * Classifies one structured extraction against the raw line it came from.
 * `outcome` is the extractor result, or `{ thrown }` when the extractor raised.
 * Pair accounting is defined for key=value bodies; for other body formats only
 * the UNKNOWN/ERROR distinctions are decided here and the Semantic Golden
 * Oracle carries the field-level proof.
 */
export function classifyStructuredParse(
  raw: string,
  outcome: StructuredOutcome | { thrown: unknown },
  bodyFormat: string,
): ParseVerdict {
  if ('thrown' in outcome) return { status: 'ERROR', lostPairs: [], reasons: ['extractor raised: ' + String(outcome.thrown)] };
  if (outcome.errors.length > 0) return { status: 'UNKNOWN', lostPairs: [], reasons: outcome.errors.slice(0, 4) };
  if (Object.keys(outcome.fields).length === 0) return { status: 'UNKNOWN', lostPairs: [], reasons: ['no field was extracted'] };
  // A TAG ("kernel:") or a pair ("srcip=10.1.1.1") read as the RFC 3164 host name is a misread header, whatever
  // the grammar matched. Only a result of the RFC 3164 header grammar is judged (it carries the mark below): a
  // JSON or key=value field called syslog_hostname is data, and an RFC 5424 HOSTNAME is positional.
  const host = getTag(outcome, 'rfc3164Header') === true ? outcome.fields.syslog_hostname : undefined;
  const headerReasons = typeof host === 'string' && (host.includes('=') || host.endsWith(':'))
    ? ['a TAG or a key=value pair was taken as the host name'] : [];
  if (bodyFormat !== 'kv') return { status: headerReasons.length ? 'PARTIAL' : 'FULL', lostPairs: [], reasons: headerReasons };
  // The pairs of the raw line are looked up where the key=value parser put them: in the body of a Syslog
  // result, or in the result itself when the whole event is key=value. Header fields and RFC 5424 structured
  // data are not searched, so an SD-PARAM with the name and value of a lost pair cannot stand in for it.
  const body = outcome.fields.body;
  const scope = body !== null && typeof body === 'object' && !Array.isArray(body) ? body : outcome.fields;
  const leaves = new Map<string, string[]>();
  collectLeaves(scope, '', leaves);
  // Every pair of the raw line needs a value of its own in the result: a field written twice and present
  // once is a lost occurrence (owner policy D-1), so a matched value is consumed.
  const taken = new Map<string, Set<number>>();
  const lostPairs = independentKeyValuePairs(raw).filter(pair => {
    // An unquoted value has no escapes: the field holds the text as written, or the value was changed on the
    // way (a decoded backslash is a lost character). Which backslashes a grammar decodes in a QUOTED value is
    // the grammar's business; there presence of the value is accounted, compared with backslashes removed.
    const values = leaves.get(pair.key) ?? [];
    const consumed = taken.get(pair.key) ?? new Set<number>();
    const at = values.findIndex((value, index) => !consumed.has(index) &&
      (pair.quoted ? value === pair.value || value === pair.rawValue || value.split('\\').join('') === pair.rawValue.split('\\').join('') : value === pair.rawValue));
    if (at < 0) return true;
    consumed.add(at);
    taken.set(pair.key, consumed);
    return false;
  });
  if (lostPairs.length > 0 || headerReasons.length > 0) {
    return {
      status: 'PARTIAL',
      lostPairs,
      reasons: [...headerReasons, ...lostPairs.slice(0, 4).map(pair => `raw pair ${pair.key}= is not present with its value in the extracted fields`)],
    };
  }
  return { status: 'FULL', lostPairs: [], reasons: [] };
}
