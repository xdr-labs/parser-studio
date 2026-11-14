import { describe, expect, it } from 'vitest';
import { extractStructuredFamily } from '../structuredFamilies';
import { classifyStructuredParse } from './parseStatus';
import { generateRfc5424KvCases } from './rfc5424Model';

const at = (value: unknown, path: string): unknown =>
  path.split('.').reduce<unknown>((node, key) => (node !== null && typeof node === 'object' ? (node as Record<string, unknown>)[key] : undefined), value);

describe('RFC 5424 lines with a key=value MSG', () => {
  it('meets every model expectation, with a FULL verdict only when nothing is lost', () => {
    for (const item of generateRfc5424KvCases(120, 20261115)) {
      const out = extractStructuredFamily(item.raw, 'syslog_rfc5424', 'kv');
      const verdict = classifyStructuredParse(item.raw, out, 'kv');
      if (item.expect.status === 'UNKNOWN') { expect(verdict.status, item.id + ' ' + JSON.stringify(item.raw)).toBe('UNKNOWN'); continue; }
      if (item.expect.neverWrong && verdict.status === 'UNKNOWN') continue;
      expect(verdict.status, item.id + ' ' + JSON.stringify(item.raw) + ' ' + out.errors.join()).toBe('FULL');
      for (const [path, want] of Object.entries(item.expect.source ?? {})) expect(at(out.fields, path), `${item.id} ${path}`).toEqual(want);
    }
  });

  it('declines what the RFC does not allow', () => {
    const head = '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47';
    for (const raw of [
      head.replace(' evntslog', '  evntslog') + ' - srcip=10.1.1.1',   // two SP: an empty header field
      head + ' srcip=10.1.1.1',                                         // STRUCTURED-DATA missing
      head.replace('<165>', '<192>') + ' - srcip=10.1.1.1',             // PRI above 191
      head.replace('2003-10-11', '2026-02-30') + ' - srcip=10.1.1.1',   // not a calendar day
    ]) expect(extractStructuredFamily(raw, 'syslog_rfc5424', 'kv').errors.length, raw).toBeGreaterThan(0);
  });
});
