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

export interface StructuredOutcome { fields: Record<string, unknown>; errors: string[] }
export interface RawPair { key: string; value: string; rawValue: string }
export interface ParseVerdict { status: ParseStatus; lostPairs: RawPair[]; reasons: string[] }

const KEY_AT_TOKEN_START = /^[A-Za-z_][A-Za-z0-9_.-]{0,95}=/;

/**
 * Independent evidence: key=value pairs that start a whitespace-separated token
 * of the raw line. Quoted values are consumed whole, so a '=' inside a quoted
 * value is never reported as a pair of its own. This is intentionally not the
 * product KV parser.
 */
export function independentKeyValuePairs(raw: string): RawPair[] {
  const pairs: RawPair[] = [];
  const length = raw.length;
  let index = 0;
  while (index < length) {
    while (index < length && (raw[index] === ' ' || raw[index] === '\t')) index += 1;
    const start = index;
    const key = KEY_AT_TOKEN_START.exec(raw.slice(index, index + 98));
    if (key) {
      index += key[0].length;
      if (raw[index] === '"') {
        let cursor = index + 1;
        let value = '';
        let closed = false;
        while (cursor < length) {
          if (raw[cursor] === '\\' && cursor + 1 < length) { value += raw[cursor + 1]; cursor += 2; continue; }
          if (raw[cursor] === '"') { closed = true; break; }
          value += raw[cursor]; cursor += 1;
        }
        if (closed) {
          pairs.push({ key: key[0].slice(0, -1), value, rawValue: raw.slice(index + 1, cursor) });
          index = cursor + 1;
          continue;
        }
      }
      let end = index;
      while (end < length && raw[end] !== ' ' && raw[end] !== '\t') end += 1;
      const value = raw.slice(index, end);
      pairs.push({ key: key[0].slice(0, -1), value, rawValue: value });
      index = end;
      continue;
    }
    while (index < length && raw[index] !== ' ' && raw[index] !== '\t') index += 1;
    if (index === start) index += 1;
  }
  return pairs;
}

function collectLeaves(value: unknown, key: string, out: Map<string, string[]>): void {
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
  if (bodyFormat !== 'kv') return { status: 'FULL', lostPairs: [], reasons: [] };
  const leaves = new Map<string, string[]>();
  collectLeaves(outcome.fields, '', leaves);
  const lostPairs = independentKeyValuePairs(raw).filter(pair => {
    const values = leaves.get(pair.key) ?? [];
    return !values.some(value => value === pair.value || value === pair.rawValue);
  });
  if (lostPairs.length > 0) {
    return {
      status: 'PARTIAL',
      lostPairs,
      reasons: lostPairs.slice(0, 4).map(pair => `raw pair ${pair.key}= is not present with its value in the extracted fields`),
    };
  }
  return { status: 'FULL', lostPairs: [], reasons: [] };
}
