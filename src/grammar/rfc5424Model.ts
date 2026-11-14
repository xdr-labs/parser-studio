/**
 * Property-based case generator for RFC 5424 lines with a key=value MSG.
 *
 * A line is rendered from a model of the header fields (RFC 5424 section 6:
 * "<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP
 * STRUCTURED-DATA [SP MSG]") and of the pairs the sender meant. The
 * expectation is the meant value of every field, never the result of parsing.
 *
 * Only facts the RFC states are claimed: exactly one SP between header fields,
 * STRUCTURED-DATA is NILVALUE or SD-ELEMENTs, PRI is 0..191, the timestamp is a
 * real RFC 3339 instant. How a NILVALUE header field is represented is a
 * product choice, so a NILVALUE field carries no expectation. VERSION follows
 * the contract policy (semantics.rfc5424SupportedVersions).
 */
import type { OracleCase, OracleExpectation } from './syslogHeaderModel';

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

const TIMESTAMPS = ['2003-10-11T22:14:15.003Z', '1985-04-12T23:20:50.52Z', '2003-08-24T05:14:15.000003-07:00', '2024-02-29T12:00:00+09:00', '2026-11-14T05:00:00Z'];
const HOSTS = ['mymachine.example.com', '192.0.2.1', 'fw01', '-'];
const APPS = ['evntslog', 'su', 'fw-agent', '-'];
const PROCIDS = ['-', '1234', 'proc.77'];
const MSGIDS = ['ID47', 'TCPIN', '-'];
const PLAIN: Readonly<Record<string, readonly string[]>> = {
  srcip: ['10.1.1.1', '192.168.0.254'], dstip: ['10.2.2.2', '8.8.8.8'], srcport: ['1', '65535'], dstport: ['443', '22'], action: ['accept', 'deny'],
};
const NOTES: ReadonlyArray<readonly [string, string]> = [['hello world', '"hello world"'], ['a b', 'a b'], ['a=b c', '"a=b c"'], ['ok', 'ok']];

interface Model { pri: number; timestamp: string; host: string; app: string; procid: string; msgid: string; pairs: Array<[string, string, string]> }

function expectation(model: Model, sd: null | { id: string; params: Array<[string, string]> }): OracleExpectation {
  const source: Record<string, unknown> = { syslog_pri: model.pri, syslog_version: 1, syslog_timestamp: model.timestamp };
  if (model.host !== '-') source.syslog_hostname = model.host;
  if (model.app !== '-') source.syslog_appname = model.app;
  if (model.procid !== '-') source.syslog_procid = model.procid;
  if (model.msgid !== '-') source.syslog_msgid = model.msgid;
  if (sd) {
    source['syslog_sd.element_1.sd_id'] = sd.id;
    for (const [name, value] of sd.params) source[`syslog_sd.element_1.params.${name}`] = value;
  }
  const values = new Map(model.pairs.map(([key, value]) => [key, value]));
  for (const [key, value] of model.pairs) source['body.' + key] = value;
  const event: Record<string, unknown> = {};
  const eventAbsent: string[] = [];
  for (const key of ['srcip', 'dstip', 'action']) if (values.has(key)) event[key] = values.get(key); else eventAbsent.push(key);
  for (const key of ['srcport', 'dstport']) if (values.has(key)) event[key] = Number(values.get(key)); else eventAbsent.push(key);
  if (values.has('note')) event['Synthetic.note'] = values.get('note'); else eventAbsent.push('Synthetic.note');
  event.stellar_log_index = values.get('action') === 'deny' ? 'threat' : values.has('srcip') ? 'session' : 'syslog';
  return { status: 'FULL', source, sourceAbsent: [], event, eventAbsent };
}

const UNKNOWN: OracleExpectation = { status: 'UNKNOWN', event: null };

export function generateRfc5424KvCases(count: number, seed: number): OracleCase[] {
  const random = mulberry32(seed);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const cases: OracleCase[] = [];
  for (let index = 0; index < count; index += 1) {
    const keys = Object.keys(PLAIN).sort(() => random() - 0.5).slice(0, 2 + Math.floor(random() * 3));
    const note = pick(NOTES);
    const model: Model = {
      pri: pick([0, 1, 13, 34, 134, 165, 190, 191]), timestamp: pick(TIMESTAMPS), host: pick(HOSTS), app: pick(APPS), procid: pick(PROCIDS), msgid: pick(MSGIDS),
      pairs: [...keys.map(key => { const value = pick(PLAIN[key]!); return [key, value, value] as [string, string, string]; }), ['note', note[0], note[1]]],
    };
    const body = model.pairs.map(([key, , text]) => key + '=' + text).join(' ');
    const header = (overrides: Partial<{ pri: string; version: string; timestamp: string; gap: string }> = {}) =>
      `<${overrides.pri ?? model.pri}>${overrides.version ?? '1'} ` + [overrides.timestamp ?? model.timestamp, model.host, model.app, model.procid, model.msgid].join(overrides.gap ?? ' ');
    const add = (variant: string, raw: string, expect: OracleExpectation) => cases.push({
      id: `rfc5424-${seed}-${index}-${variant}`, grammar: 'syslog_rfc5424', body: 'kv', raw,
      provenance: `model-rendered RFC 5424 line (${variant}); expectation is the meant value of every header field and pair`, expect,
    });
    add('nil-structured-data', header() + ' - ' + body, expectation(model, null));
    const sd = { id: 'exampleSDID@32473', params: [['iut', '3'], ['eventSource', 'Application']] as Array<[string, string]> };
    add('one-sd-element', header() + ' [' + sd.id + ' ' + sd.params.map(([name, value]) => `${name}="${value}"`).join(' ') + '] ' + body, expectation(model, sd));
    // A header field may be the NILVALUE; a NILVALUE timestamp is allowed by the RFC, so an engine may decline it but must not misread it.
    add('nil-timestamp', header({ timestamp: '-' }) + ' - ' + body, { ...expectation({ ...model }, null), neverWrong: true, source: Object.fromEntries(Object.entries(expectation(model, null).source ?? {}).filter(([key]) => key !== 'syslog_timestamp')) });
    add('version-2', header({ version: '2' }) + ' - ' + body, UNKNOWN);
    add('pri-192', header({ pri: '192' }) + ' - ' + body, UNKNOWN);
    add('february-30', header({ timestamp: '2026-02-30T22:14:15Z' }) + ' - ' + body, UNKNOWN);
    // Two SP between header fields leave an empty field, which the RFC does not allow.
    add('double-space-in-header', header({ gap: '  ' }) + ' - ' + body, UNKNOWN);
    // STRUCTURED-DATA is NILVALUE or SD-ELEMENTs; with it missing, the MSG stands where it must be.
    add('structured-data-missing', header() + ' ' + body, UNKNOWN);
  }
  return cases;
}
