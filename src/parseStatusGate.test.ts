/**
 * Parsing Success Contract wired into the preview pipeline (W7).
 *
 * The product extractor is wrapped so a test can make it lose a field the way
 * defect F-1 did: the first key=value pair goes into the host name and the
 * extractor still reports no error. The pipeline must then refuse to call the
 * event parsed. Without the fault the same line is FULL.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

const fault = vi.hoisted(() => ({ loseFirstPair: false, raise: false }));
vi.mock('./structuredFamilies', async (original) => {
  const actual = await original<typeof import('./structuredFamilies')>();
  return {
    ...actual,
    extractStructuredFamily: (...args: Parameters<typeof actual.extractStructuredFamily>) => {
      const out = actual.extractStructuredFamily(...args);
      if (!fault.loseFirstPair || out.errors.length) return out;
      const body = { ...(out.fields.body as Record<string, unknown>) };
      const first = Object.keys(body)[0]!;
      const swallowed = first + '=' + String(body[first]);
      delete body[first];
      return { errors: [], fields: { ...out.fields, syslog_hostname: swallowed, body } };
    },
  };
});

import { preview } from './parser';
import { createDraft } from './model';
import { independentKeyValuePairs } from './grammar/parseStatus';

const draft = (format: 'syslog_rfc3164' | 'syslog_rfc5424') => ({ ...createDraft(), format, syslogBodyFormat: 'kv' as const });
const RFC3164 = '<134>Nov 13 10:00:00 fw01 srcip=10.1.1.1 dstip=10.2.2.2 action=deny';
const HOSTLESS = '<134>Nov 13 10:00:00 srcip=10.1.1.1 dstip=10.2.2.2 action=deny';
const RFC5424 = '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 - srcip=10.1.1.1 action=accept';

describe('Parsing Success Contract in the preview pipeline', () => {
  afterEach(() => { fault.loseFirstPair = false; });

  it.each([[RFC3164, 'syslog_rfc3164'], [HOSTLESS, 'syslog_rfc3164'], [RFC5424, 'syslog_rfc5424']] as const)(
    'reports FULL for %j when every pair of the original line is in the result', (raw, format) => {
      const event = preview(raw, draft(format)).events[0]!;
      expect(event.parseStatus).toBe('FULL');
      expect(event.diagnostics.filter(item => item.code === 'FIELD_LOSS_NOT_FULL')).toEqual([]);
      expect(event.extracted).toBe(true);
    });

  it.each([[RFC3164, 'syslog_rfc3164'], [HOSTLESS, 'syslog_rfc3164'], [RFC5424, 'syslog_rfc5424']] as const)(
    'never reports %j as parsed when the extractor silently loses a pair', (raw, format) => {
      fault.loseFirstPair = true;
      const suite = preview(raw, draft(format));
      const event = suite.events[0]!;
      expect(event.parseStatus).toBe('PARTIAL');
      expect(event.status).toBe('fail');
      expect(suite.counts.failures).toBe(1);
      const loss = event.diagnostics.filter(item => item.code === 'FIELD_LOSS_NOT_FULL');
      expect(loss).toHaveLength(1);
      expect(loss[0]!.severity).toBe('error');
      expect(loss[0]!.message).toContain('srcip');
      expect(event.raw).toBe(raw);
    });

  it('reports UNKNOWN, not FULL, for a line the grammar declines', () => {
    const event = preview('<134>Nov 13 10:00:00 fw01 srcip=10.1.1.1 stray action=deny', draft('syslog_rfc3164')).events[0]!;
    expect(event.parseStatus).toBe('UNKNOWN');
    expect(event.status).toBe('fail');
  });

  it('treats the positional RFC 5424 header fields as header, not as lost pairs', () => {
    const raw = '<34>1 2026-10-11T22:14:15Z a=b app 123 ID47 - k=1 m=2';
    expect(independentKeyValuePairs(raw).map(pair => pair.key)).toEqual(['k', 'm']);
    expect(preview(raw, draft('syslog_rfc5424')).events[0]!.parseStatus).toBe('FULL');
    // RFC 3164 has no such exemption: a pair right after the timestamp is counted.
    expect(independentKeyValuePairs(HOSTLESS).map(pair => pair.key)).toEqual(['srcip', 'dstip', 'action']);
  });
});
