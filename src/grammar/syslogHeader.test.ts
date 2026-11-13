import { describe, expect, it } from 'vitest';
import { independentKeyValuePairs, classifyStructuredParse } from './parseStatus';
import { isSupportedRfc5424Version, matchHeaderRule, matchRfc3164Header, matchRfc5424Header } from './syslogHeader';
import { SYSLOG_HEADER_RULES, SYSLOG_HEADER_SEMANTICS } from './syslogHeaderGrammar.generated';
import { generateRfc3164KvCases } from './syslogHeaderModel';
import { detectStructuredFamily, extractStructuredFamily } from '../structuredFamilies';
import { parseSyslogEnvelope } from '../syslogEnvelope';

describe('contract-driven RFC 3164 header', () => {
  it('reads a tagged header by capture name', () => {
    expect(matchRfc3164Header('<134>Nov 13 10:00:00 fw01 kernel[77]: srcip=10.1.1.1 action=deny')).toEqual({
      ok: true, rule: 'rfc3164_tagged', pri: 134, timestamp: 'Nov 13 10:00:00', hostname: 'fw01',
      tag: 'kernel', procid: '77', message: 'srcip=10.1.1.1 action=deny',
    });
  });

  it('never takes a key=value token as the host name (F-1)', () => {
    const header = matchRfc3164Header('<134>Nov 13 10:00:00 srcip=10.1.1.1 dstip=10.2.2.2 action=accept');
    expect(header).toEqual({
      ok: true, rule: 'rfc3164_hostless', pri: 134, timestamp: 'Nov 13 10:00:00',
      message: 'srcip=10.1.1.1 dstip=10.2.2.2 action=accept',
    });
  });

  it.each([
    ['CEF', '<134>Nov 13 10:00:00 CEF:0|Acme|FW|1.0|100|Conn|5|src=10.1.1.1 dst=10.2.2.2'],
    ['LEEF', 'Nov 13 10:00:00 LEEF:1.0|Acme|FW|1.0|100|src=10.1.1.1'],
    ['JSON', '<134>Nov 13 10:00:00 {"src": "10.1.1.1", "dst": "10.2.2.2"}'],
  ])('keeps a %s body whole when the host name is omitted', (_name, raw) => {
    const header = matchRfc3164Header(raw);
    expect(header.ok && header.rule).toBe('rfc3164_hostless');
    expect(header.ok && header.hostname).toBeUndefined();
    expect(header.ok && raw.endsWith(header.message)).toBe(true);
  });

  it('accepts U+2028 inside the message like the Ruby runtime does (F-3)', () => {
    const header = matchRfc3164Header('<134>Nov 13 10:00:00 fw01 srcip=10.1.1.1 note=a b');
    expect(header.ok && header.message).toBe('srcip=10.1.1.1 note=a b');
  });

  it.each([
    ['<192>Nov 13 10:00:00 fw01 a=b', 'PRI_OUT_OF_RANGE'],
    ['<134>Feb 30 10:00:00 fw01 a=b', 'CALENDAR_INVALID'],
    ['<134>Nov 13 24:00:00 fw01 a=b', 'CALENDAR_INVALID'],
    ['<134>Nov 13 10:00:00\tfw01 a=b', 'NO_MATCH'],
    ['<134>Nov 13 10:00:00 fw01 a=b\nsecond line', 'NO_MATCH'],
  ])('rejects %j as %s', (raw, reason) => {
    expect(matchRfc3164Header(raw)).toEqual({ ok: false, reason });
  });

  it('keeps the hostless rule disjoint from the rules that read a host name', () => {
    let hostless = 0;
    for (const item of generateRfc3164KvCases(120, 7)) {
      const withHost = matchHeaderRule('rfc3164_tagged', item.raw) !== null || matchHeaderRule('rfc3164_tagless', item.raw) !== null;
      const withoutHost = matchHeaderRule('rfc3164_hostless', item.raw) !== null;
      expect(withHost && withoutHost, item.raw).toBe(false);
      if (withoutHost) hostless += 1;
    }
    expect(hostless).toBeGreaterThan(100);
  });
});

describe('contract-driven RFC 5424 header', () => {
  const line = (version: string) => `<165>${version} 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 - an application event`;

  it('reads VERSION 1 by capture name', () => {
    expect(matchRfc5424Header(line('1'))).toEqual({
      ok: true, pri: 165, version: '1', timestamp: '2003-10-11T22:14:15.003Z', hostname: 'mymachine.example.com',
      appname: 'evntslog', procid: '-', msgid: 'ID47', rest: '- an application event',
    });
  });

  it.each(['2', '12', '999'])('declines the undefined VERSION %s everywhere (F-2)', version => {
    expect(matchRfc5424Header(line(version))).toEqual({ ok: false, reason: 'VERSION_UNSUPPORTED' });
    expect(isSupportedRfc5424Version(version)).toBe(false);
  });

  it('treats a malformed VERSION as no RFC 5424 header at all', () => {
    expect(matchRfc5424Header(line('0'))).toEqual({ ok: false, reason: 'NO_MATCH' });
    expect(matchRfc5424Header(line('1000'))).toEqual({ ok: false, reason: 'NO_MATCH' });
  });

  it('enforces the RFC 5424 token length limits from the contract', () => {
    const long = (size: number) => `<165>1 2003-10-11T22:14:15.003Z host ${'a'.repeat(size)} - ID47 - message`;
    expect(matchRfc5424Header(long(48)).ok).toBe(true);
    expect(matchRfc5424Header(long(49)).ok).toBe(false);
  });
});

describe('generated grammar', () => {
  it('uses no runtime-dependent construct', () => {
    for (const rule of Object.values(SYSLOG_HEADER_RULES)) {
      expect(rule.source).not.toMatch(/\\[dwsDWSb]/);
      expect(rule.source.replace(/\\./g, '').replace(/\[[^\]]*\]/g, '')).not.toContain('.');
    }
    expect(SYSLOG_HEADER_SEMANTICS.priMax).toBe(191);
  });
});

/** Strict key=value body used only to drive the header through the model: every token must be a pair. */
function strictPairs(message: string): Array<[string, string]> | null {
  const pairs = independentKeyValuePairs(message);
  const rebuilt = pairs.map(pair => pair.key + '=' + (message.includes(`${pair.key}="${pair.rawValue}"`) ? `"${pair.rawValue}"` : pair.rawValue)).join(' ');
  return rebuilt === message.trim().replace(/ +/g, ' ') ? pairs.map(pair => [pair.key, pair.value]) : null;
}

describe('model-based properties of the contract grammar', () => {
  it('meets every independently stated expectation, including the variants the legacy grammar fails', () => {
    const cases = generateRfc3164KvCases(300, 20261113);
    expect(cases.length).toBeGreaterThan(2700);
    for (const item of cases) {
      const header = matchRfc3164Header(item.raw);
      const pairs = header.ok ? strictPairs(header.message) : null;
      const parsed = header.ok && pairs !== null;
      if (item.expect.status === 'UNKNOWN') { expect(parsed, item.id).toBe(false); continue; }
      if (!parsed) { expect(item.expect.neverWrong, item.id + ' ' + JSON.stringify(item.raw)).toBe(true); continue; }
      const fields: Record<string, unknown> = {
        syslog_timestamp: header.timestamp,
        ...(header.pri === undefined ? {} : { syslog_pri: header.pri }),
        ...(header.hostname === undefined ? {} : { syslog_hostname: header.hostname }),
        ...(header.tag === undefined ? {} : { syslog_appname: header.tag }),
        ...(header.procid === undefined ? {} : { syslog_procid: header.procid }),
      };
      for (const [key, value] of pairs!) fields['body.' + key] = value;
      for (const [path, want] of Object.entries(item.expect.source ?? {})) expect(fields[path], `${item.id} ${path}`).toEqual(want);
      for (const path of item.expect.sourceAbsent ?? []) expect(fields[path], `${item.id} ${path}`).toBeUndefined();
    }
  });
});

describe('parsing success contract', () => {
  it('refuses FULL when a raw key=value pair is missing from the extracted fields', () => {
    const raw = '<134>Nov 13 10:00:00 srcip=10.1.1.1 dstip=10.2.2.2 action=accept';
    const swallowed = { fields: { syslog_hostname: 'srcip=10.1.1.1', body: { dstip: '10.2.2.2', action: 'accept' } }, errors: [] };
    const verdict = classifyStructuredParse(raw, swallowed, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['srcip']);
  });

  it('grants FULL only when every raw pair is present with its value', () => {
    const raw = '<134>Nov 13 10:00:00 fw01 srcip=10.1.1.1 msg="a=b c" count=7';
    const fields = { syslog_hostname: 'fw01', body: { srcip: '10.1.1.1', msg: 'a=b c', count: 7 } };
    expect(classifyStructuredParse(raw, { fields, errors: [] }, 'kv').status).toBe('FULL');
    expect(classifyStructuredParse(raw, { fields: { ...fields, body: { ...fields.body, srcip: '10.1.1.9' } }, errors: [] }, 'kv').status).toBe('PARTIAL');
  });

  it('separates UNKNOWN from ERROR', () => {
    expect(classifyStructuredParse('x', { fields: {}, errors: ['unsupported'] }, 'kv').status).toBe('UNKNOWN');
    expect(classifyStructuredParse('x', { fields: {}, errors: [] }, 'kv').status).toBe('UNKNOWN');
    expect(classifyStructuredParse('x', { thrown: new Error('boom') }, 'kv').status).toBe('ERROR');
  });

  it('does not report a pair that only exists inside a quoted value', () => {
    expect(independentKeyValuePairs('a=1 msg="x=y z=w" b=2').map(pair => pair.key)).toEqual(['a', 'msg', 'b']);
  });
});

describe('consumers follow the contract', () => {
  it('labels an RFC 5424 shaped line as RFC 5424 only for a supported VERSION (F-2)', () => {
    const line = (version: string) => `<34>${version} 2026-10-11T22:14:15Z host app 123 ID47 - a=1 b=2`;
    expect(detectStructuredFamily(line('1'))).toBe('syslog_rfc5424');
    for (const version of ['2', '10']) {
      expect(detectStructuredFamily(line(version)), version).not.toBe('syslog_rfc5424');
      expect(parseSyslogEnvelope(line(version)), version).toBeNull();
      expect(extractStructuredFamily(line(version), 'syslog_rfc5424', 'kv').errors.length, version).toBe(1);
    }
  });

  it('detects the BSD forms by syntax and leaves calendar errors to extraction', () => {
    expect(detectStructuredFamily('Feb 30 00:00:00 fw01 a=1 b=2')).toBe('syslog_rfc3164');
    expect(extractStructuredFamily('Feb 30 00:00:00 fw01 a=1 b=2', 'syslog_rfc3164', 'kv').errors).toEqual(['RFC3164 PRI or calendar value is invalid']);
    expect(detectStructuredFamily('<134>Nov 13 10:00:00 srcip=10.1.1.1 action=accept')).toBe('syslog_rfc3164');
  });

  it('never reads a TAG as the host name when HOSTNAME is omitted (F-5)', () => {
    for (const raw of ['<13>Oct 11 22:14:15 kernel: a=1 b=2', 'Oct 11 22:14:15 sshd[123]: a=1 b=2']) {
      const result = extractStructuredFamily(raw, 'syslog_rfc3164', 'kv');
      expect(result.fields.syslog_hostname, raw).toBeUndefined();
      expect(result.errors.length, raw).toBe(1);
    }
  });

  it('keeps U+2028 inside the message of a generic Syslog envelope, like the Ruby export (F-3)', () => {
    const envelope = parseSyslogEnvelope('<34>1 2026-10-11T22:14:15Z host app 123 ID47 - user=a\u2028b x=1');
    expect(envelope?.variant).toBe('rfc5424');
    expect(envelope?.message).toBe('user=a\u2028b x=1');
  });
});
