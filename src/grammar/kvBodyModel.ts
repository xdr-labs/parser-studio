/**
 * Property-based case generator for the strict key=value body.
 *
 * A case is rendered from a model: a list of pairs, each with the value the
 * sender MEANT and the way it is written (bare, double-quoted, single-quoted,
 * escaped). The expectation is the meant value, never the result of parsing
 * the rendered text. Every variant states its own expected behaviour.
 *
 * Bodies are wrapped in a fixed RFC 3164 header so the same executors are used
 * as for the header cases; native expectations assume the oracle profile
 * `fw-kv` (srcip/dstip/srcport/dstport/action plus vendor fields note, path
 * and user).
 */
import type { OracleCase, OracleExpectation } from './syslogHeaderModel';

const HEADER = '<134>Nov 13 10:00:00 fw01 ';

interface Pair { key: string; value: string; text: string }

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** [meant value, text after "key="] */
const WRITTEN: ReadonlyArray<readonly [string, string]> = [
  ['ok', 'ok'],
  ['hello world', '"hello world"'],
  ['a=b c', '"a=b c"'],
  ['say "hi" now', '"say \\"hi\\" now"'],
  ["it's here", '"it\'s here"'],
  ['it is', "'it is'"],
  ["rock 'n' roll", "'rock \\'n\\' roll'"],
  ['C:\\Users\\x', '"C:\\Users\\x"'],
  ['C:\\Windows\\System32', 'C:\\Windows\\System32'],
  ['a\\b', '"a\\\\b"'],
  ['k=v', 'k\\=v'],
  ['a\\ b', 'a\\ b'],
  ['a\u2028b', 'a\u2028b'],
  ['a\u00a0b', 'a\u00a0b'],
  ['\uD55C\uAD6D\uC5B4 \uB85C\uADF8', '"\uD55C\uAD6D\uC5B4 \uB85C\uADF8"'],
  ['x', "'x'"],
];
const TRICKY_KEYS = ['note', 'path', 'user'];
const PLAIN: Readonly<Record<string, readonly string[]>> = {
  srcip: ['10.1.1.1', '192.168.0.254'], dstip: ['10.2.2.2', '8.8.8.8'],
  srcport: ['1', '65535'], dstport: ['443', '22'], action: ['accept', 'deny'],
  k1: ['0', '18446744073709551615'], k2: ['-', 'n/a'], k3: ['http://x/?a=b'],
};

function buildPairs(random: () => number): Pair[] {
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const keys = [...Object.keys(PLAIN), ...TRICKY_KEYS].sort(() => random() - 0.5).slice(0, 2 + Math.floor(random() * 6));
  return keys.map(key => {
    if (TRICKY_KEYS.includes(key)) {
      const [value, text] = pick(WRITTEN);
      return { key, value, text };
    }
    const value = pick(PLAIN[key]!);
    return { key, value, text: value };
  });
}

/** Joins pairs; a quoted pair may be followed directly by the next key, as the grammar allows. */
function renderBody(pairs: Pair[], separator: (index: number, previous: Pair) => string): string {
  return pairs.map((pair, index) => (index === 0 ? '' : separator(index, pairs[index - 1]!)) + pair.key + '=' + pair.text).join('');
}

function full(pairs: Pair[]): OracleExpectation {
  const values = new Map(pairs.map(pair => [pair.key, pair.value]));
  const source: Record<string, unknown> = { syslog_hostname: 'fw01' };
  for (const pair of pairs) source['body.' + pair.key] = pair.value;
  const event: Record<string, unknown> = {};
  const eventAbsent: string[] = [];
  for (const key of ['srcip', 'dstip', 'action']) if (values.has(key)) event[key] = values.get(key); else eventAbsent.push(key);
  for (const key of ['srcport', 'dstport']) if (values.has(key)) event[key] = Number(values.get(key)); else eventAbsent.push(key);
  for (const key of TRICKY_KEYS) if (values.has(key)) event['Synthetic.' + key] = values.get(key); else eventAbsent.push('Synthetic.' + key);
  event.stellar_log_index = values.get('action') === 'deny' ? 'threat' : values.has('srcip') ? 'session' : 'syslog';
  return { status: 'FULL', source, sourceAbsent: [], event, eventAbsent };
}

const UNKNOWN: OracleExpectation = { status: 'UNKNOWN', event: null };

export function generateKvBodyCases(count: number, seed: number): OracleCase[] {
  const random = mulberry32(seed);
  const cases: OracleCase[] = [];
  for (let index = 0; index < count; index += 1) {
    const pairs = buildPairs(random);
    const add = (variant: string, body: string, expect: OracleExpectation) => cases.push({
      id: `kv-${seed}-${index}-${variant}`, grammar: 'syslog_rfc3164', body: 'kv', raw: HEADER + body,
      provenance: `model-rendered key=value body (${variant}); expectation is the meant value of each pair`, expect,
    });
    const quoted = (pair: Pair) => /^["'].*["']$/.test(pair.text);
    add('single-space', renderBody(pairs, () => ' '), full(pairs));
    add('double-space-and-tab', renderBody(pairs, at => (at % 2 ? '  ' : '\t')), full(pairs));
    add('trailing-white-space', renderBody(pairs, () => ' ') + ' \t ', full(pairs));
    // No separator after a closing quote is still one pair boundary.
    add('adjacent-after-quote', renderBody(pairs, (_at, previous) => (quoted(previous) ? '' : ' ')), full(pairs));
    add('reversed', renderBody([...pairs].reverse(), () => ' '), full([...pairs].reverse()));
    add('duplicate-key', renderBody([...pairs, { ...pairs[0]!, value: 'again', text: 'again' }], () => ' '), UNKNOWN);
    add('forbidden-key', renderBody([...pairs, { key: '__proto__', value: '1', text: '1' }], () => ' '), UNKNOWN);
    add('token-without-equals', renderBody(pairs, at => (at === 1 ? ' stray ' : ' ')), UNKNOWN);
    add('unterminated-quote', renderBody(pairs, () => ' ') + ' tail="never closed', UNKNOWN);
    // Issue #214: U+001C..U+001F are information separators, never part of a bare value and never a pair separator.
    const control = String.fromCharCode(0x1c + (index % 4));
    add('control-separator-in-bare-value', renderBody(pairs, () => ' ') + ' tail=' + control + 'deny', UNKNOWN);
    add('control-separator-between-pairs', renderBody(pairs, at => (at === 1 ? control : ' ')), pairs.length > 1 ? UNKNOWN : full(pairs));
  }
  const many = (size: number): Pair[] => Array.from({ length: size }, (_unused, at) => ({ key: 'f' + at, value: String(at), text: String(at) }));
  const limit = (size: number, expect: OracleExpectation) => cases.push({
    id: `kv-${seed}-limit-${size}`, grammar: 'syslog_rfc3164', body: 'kv', raw: HEADER + renderBody(many(size), () => ' '),
    provenance: 'pair limit boundary (semantics.kvMaxPairs = 100)', expect,
  });
  limit(100, { status: 'FULL', source: { 'body.f0': '0', 'body.f99': '99' }, sourceAbsent: [], event: { stellar_log_index: 'syslog' }, eventAbsent: [] });
  limit(101, UNKNOWN);
  return cases;
}
