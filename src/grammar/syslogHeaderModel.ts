/**
 * Property-based / metamorphic case generator for the RFC 3164 header with a
 * key=value body.
 *
 * Each case is rendered FROM A MODEL (the intended PRI, timestamp, host, tag and
 * pairs), and its expectation is computed from that model, never by parsing the
 * rendered line. Variants do not assume "same result as the base case": every
 * variant states its own expected behaviour (FULL with these exact fields,
 * UNKNOWN, or NEVER_WRONG = either the exact fields or not parsed at all).
 *
 * Native expectations assume the oracle mapping profile `fw-kv`
 * (contracts/semantic-goldens.v1.json): srcip/dstip as ip, srcport/dstport as
 * port, action as string, HOSTNAME under the vendor namespace, and the
 * classification deny -> threat, srcip present -> session, otherwise syslog.
 */
export interface OracleExpectation {
  status: 'FULL' | 'UNKNOWN';
  /** FULL only: when true the engine may instead decline to parse, but must never emit different fields. */
  neverWrong?: boolean;
  source?: Record<string, unknown>;
  sourceAbsent?: string[];
  event?: Record<string, unknown> | null;
  eventAbsent?: string[];
}
export interface OracleCase {
  id: string;
  grammar: 'syslog_rfc3164' | 'syslog_rfc5424';
  body: 'kv';
  /** UNKNOWN cases only: 'body' when the header is well formed and the body is what must be declined. */
  rejectedAt?: 'body';
  raw: string;
  provenance: string;
  knownDefect?: string;
  expect: OracleExpectation;
}

const MONTH_DAYS: ReadonlyArray<readonly [string, number]> = [
  ['Jan', 31], ['Feb', 29], ['Mar', 31], ['Apr', 30], ['May', 31], ['Jun', 30],
  ['Jul', 31], ['Aug', 31], ['Sep', 30], ['Oct', 31], ['Nov', 30], ['Dec', 31],
];
const HOSTS = ['fw01', 'gw-2.example.com', '10.0.0.1', 'fe80::1', 'FW_A', 'edge.site-7'];
const TAGS = ['kernel', 'sshd', 'fw-agent', 'app.mod', '_svc'];
const VALUE_POOL: Readonly<Record<string, readonly string[]>> = {
  srcip: ['0.0.0.0', '10.1.1.1', '255.255.255.255', '192.168.0.254'],
  dstip: ['10.2.2.2', '172.16.0.1', '8.8.8.8'],
  srcport: ['1', '1234', '65535'],
  dstport: ['443', '8080', '65535'],
  action: ['accept', 'deny', 'drop'],
  proto: ['tcp', 'udp', '6'],
  user: ['alice', '한국어', 'José', 'user@example.com'],
  msg: ['a=b c', 'hello world', 'x'],
  count: ['0', '4294967295', '18446744073709551615'],
  url: ['http://x/?a=b', 'https://example.com/p?q=1&r=2'],
};
const KEYS = Object.keys(VALUE_POOL);
const QUOTED_KEYS = new Set(['msg']);

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

interface Model {
  pri: number; month: string; day: number; maxDay: number; clock: string; host: string;
  tag?: { name: string; pid?: string };
  pairs: Array<[string, string]>;
}

function buildModel(random: () => number): Model {
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const [month, maxDay] = pick(MONTH_DAYS);
  const two = (limit: number) => String(Math.floor(random() * limit)).padStart(2, '0');
  const keys = [...KEYS].sort(() => random() - 0.5).slice(0, 2 + Math.floor(random() * 4));
  return {
    pri: pick([0, 1, 13, 134, 165, 190, 191]),
    month, maxDay, day: pick([1, 9, 10, maxDay]),
    clock: `${two(24)}:${two(60)}:${two(60)}`,
    host: pick(HOSTS),
    ...(random() < 0.5 ? { tag: { name: pick(TAGS), ...(random() < 0.6 ? { pid: pick(['1', '77', '99999999']) } : {}) } } : {}),
    pairs: keys.map(key => [key, pick(VALUE_POOL[key]!)] as [string, string]),
  };
}

const renderPair = ([key, value]: [string, string]) => QUOTED_KEYS.has(key) ? `${key}="${value}"` : `${key}=${value}`;
const day2 = (day: number) => String(day).padStart(2, ' ');

interface RenderOptions {
  pri?: number | null; host?: string | null; tag?: Model['tag'] | null; day?: number;
  pairs?: Array<[string, string]>; headerGap?: string; hostSeparator?: string;
}

function render(model: Model, options: RenderOptions = {}): string {
  const pri = options.pri === undefined ? model.pri : options.pri;
  const host = options.host === undefined ? model.host : options.host;
  const tag = options.tag === undefined ? model.tag : options.tag;
  const gap = options.headerGap ?? ' ';
  const pairs = options.pairs ?? model.pairs;
  const dayText = options.headerGap ? String(options.day ?? model.day) : day2(options.day ?? model.day);
  return (pri === null ? '' : `<${pri}>`) + model.month + gap + dayText + gap + model.clock +
    (host === null ? '' : (options.hostSeparator ?? gap) + host) +
    (tag ? gap + tag.name + (tag.pid ? `[${tag.pid}]` : '') + ':' : '') + gap + pairs.map(renderPair).join(' ');
}

function fullExpectation(model: Model, shape: { pri: boolean; host: boolean; tag: boolean }, pairs = model.pairs): OracleExpectation {
  const values = new Map(pairs);
  const source: Record<string, unknown> = { syslog_timestamp: `${model.month} ${day2(model.day)} ${model.clock}` };
  const sourceAbsent: string[] = [];
  if (shape.pri) source.syslog_pri = model.pri; else sourceAbsent.push('syslog_pri');
  if (shape.host) source.syslog_hostname = model.host; else sourceAbsent.push('syslog_hostname');
  if (shape.tag && model.tag) {
    source.syslog_appname = model.tag.name;
    if (model.tag.pid) source.syslog_procid = model.tag.pid; else sourceAbsent.push('syslog_procid');
  } else sourceAbsent.push('syslog_appname', 'syslog_procid');
  for (const [key, value] of pairs) source['body.' + key] = value;
  const event: Record<string, unknown> = {};
  const eventAbsent: string[] = [];
  for (const key of ['srcip', 'dstip', 'action']) {
    if (values.has(key)) event[key] = values.get(key); else eventAbsent.push(key);
  }
  for (const key of ['srcport', 'dstport']) {
    if (values.has(key)) event[key] = Number(values.get(key)); else eventAbsent.push(key);
  }
  if (shape.host) event['Synthetic.syslog_hostname'] = model.host; else eventAbsent.push('Synthetic.syslog_hostname');
  event.stellar_log_index = values.get('action') === 'deny' ? 'threat' : values.has('srcip') ? 'session' : 'syslog';
  return { status: 'FULL', source, sourceAbsent, event, eventAbsent };
}

const UNKNOWN: OracleExpectation = { status: 'UNKNOWN', event: null };

/** Deterministic cases: `count` models, every variant of each. */
export function generateRfc3164KvCases(count: number, seed: number): OracleCase[] {
  const random = mulberry32(seed);
  const cases: OracleCase[] = [];
  for (let index = 0; index < count; index += 1) {
    const model = buildModel(random);
    const add = (variant: string, raw: string, expect: OracleExpectation, knownDefect?: string) => cases.push({
      id: `prop-${seed}-${index}-${variant}`, grammar: 'syslog_rfc3164', body: 'kv', raw,
      provenance: `model-rendered (${variant}); expectation computed from the model, not from a parser`,
      ...(knownDefect ? { knownDefect } : {}), expect,
    });
    const tagged = model.tag !== undefined;
    add('base', render(model), fullExpectation(model, { pri: true, host: true, tag: true }));
    add('double-space', render(model, { headerGap: '  ' }), fullExpectation(model, { pri: true, host: true, tag: true }));
    add('pairs-reversed', render(model, { pairs: [...model.pairs].reverse() }),
      fullExpectation(model, { pri: true, host: true, tag: true }, [...model.pairs].reverse()));
    // HOSTNAME omitted by the sender: nothing may be lost into the header.
    add('hostless', render(model, { host: null, tag: null }), fullExpectation(model, { pri: true, host: false, tag: false }));
    // PRI is optional only for the tagless form; a tagged line without PRI may be declined but never mis-parsed.
    add('no-pri', render(model, { pri: null }), tagged
      ? { ...fullExpectation(model, { pri: false, host: true, tag: true }), neverWrong: true }
      : fullExpectation(model, { pri: false, host: true, tag: false }));
    // A TAG directly after the timestamp (HOSTNAME omitted) must never be read as the host name.
    if (model.tag) add('tag-without-host', render(model, { host: null }),
      { ...fullExpectation(model, { pri: true, host: false, tag: true }), neverWrong: true });
    // The grammar separates header tokens with SP only; a TAB is not a separator.
    add('tab-before-host', render(model, { hostSeparator: '\t' }), UNKNOWN);
    add('pri-out-of-range', render(model, { pri: 192 + (index % 808) }), UNKNOWN);
    add('day-out-of-range', render(model, { day: model.maxDay + 1 }), UNKNOWN);
    // U+2028 is not a line terminator in Syslog; '.' excludes it in ECMAScript but not in Ruby.
    const withSeparator = [...model.pairs.filter(([key]) => key !== 'user'), ['user', 'a b'] as [string, string]];
    add('u2028-in-value', render(model, { pairs: withSeparator }),
      fullExpectation(model, { pri: true, host: true, tag: true }, withSeparator));
  }
  return cases;
}
