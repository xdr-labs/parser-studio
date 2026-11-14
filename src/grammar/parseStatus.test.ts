import { describe, expect, it } from 'vitest';
import { classifyStructuredParse } from './parseStatus';

const ok = (fields: Record<string, unknown>) => ({ fields, errors: [] });

describe('Parsing Success Contract: what makes a key=value result FULL', () => {
  it('is FULL when every pair of the raw line is present with its value', () => {
    const raw = '<134>Nov 14 09:30:00 fw01 srcip=10.1.1.1 msg="a=b c" action=deny';
    expect(classifyStructuredParse(raw, ok({ syslog_hostname: 'fw01', body: { srcip: '10.1.1.1', msg: 'a=b c', action: 'deny' } }), 'kv').status).toBe('FULL');
  });

  it('is PARTIAL when a pair is missing or its value differs', () => {
    const raw = 'srcip=10.1.1.1 dstip=10.2.2.2 action=deny';
    const missing = classifyStructuredParse(raw, ok({ srcip: '10.1.1.1', action: 'deny' }), 'kv');
    expect(missing.status).toBe('PARTIAL');
    expect(missing.lostPairs.map(pair => pair.key)).toEqual(['dstip']);
    expect(classifyStructuredParse(raw, ok({ srcip: '10.1', dstip: '10.2.2.2', action: 'deny' }), 'kv').status).toBe('PARTIAL');
  });

  it('counts occurrences: a field written twice and present once is a lost occurrence (owner policy D-1)', () => {
    const raw = 'action=deny srcip=192.0.2.10 action=deny';
    const verdict = classifyStructuredParse(raw, ok({ action: 'deny', srcip: '192.0.2.10' }), 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['action']);
    expect(classifyStructuredParse(raw, ok({ action: ['deny', 'deny'], srcip: '192.0.2.10' }), 'kv').status).toBe('FULL');
  });

  it('is PARTIAL when a TAG or a pair was taken as the RFC 3164 host name, whatever the body format', () => {
    for (const [raw, host] of [['<134>Nov 14 09:30:00 kernel: started', 'kernel:'], ['<134>Nov 14 09:30:00 srcip=10.1.1.1 x', 'srcip=10.1.1.1']] as const) {
      const verdict = classifyStructuredParse(raw, ok({ syslog_hostname: host, message: 'x' }), 'other');
      expect(verdict.status).toBe('PARTIAL');
      expect(verdict.reasons.join()).toContain('host name');
    }
    expect(classifyStructuredParse('<134>Nov 14 09:30:00 2001:db8::1 started', ok({ syslog_hostname: '2001:db8::1', message: 'started' }), 'other').status).toBe('FULL');
  });

  it('exempts the positional RFC 5424 HOSTNAME, which may hold any printable text', () => {
    const raw = '<165>1 2026-11-14T09:30:00Z host=a app - ID47 - srcip=10.1.1.1';
    expect(classifyStructuredParse(raw, ok({ syslog_hostname: 'host=a', body: { srcip: '10.1.1.1' } }), 'kv').status).toBe('FULL');
  });
});
