import { describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { detectFormat, extractFields, preview } from './parser';
import { toBackendProject } from './guided/backendAdapter';

const cef = 'CEF:0|Acme|Firewall|1.0|100|Denied|5|action=deny src_ip=198.51.100.10 dst_port=443';
const leef = 'LEEF:1.0|Acme|Firewall|1.0|100|action=deny\tsrc_ip=198.51.100.10\tdst_port=443';
const rfc5424 = '<34>1 2026-10-12T00:00:00Z fw app 1 EV01 - action=deny src_ip=198.51.100.10';
describe('reviewed standalone structured log families in local no-code preview', () => {
  it.each([
    ['cef', cef, 'cef_device_vendor', 'Acme'],
    ['leef', leef, 'leef_vendor', 'Acme'],
    ['syslog_rfc5424', rfc5424, 'syslog_hostname', 'fw'],
  ] as const)('%s exposes backend-compatible field names with an explicit DRAFT contract', (format, log, key, value) => {
    const draft = createDraft();
    draft.format = format;
    expect(detectFormat(log).format).toBe(format);
    const parsed = extractFields(log, format, draft);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields[key]).toBe(value);
    const converted = toBackendProject(draft);
    expect(converted.ok).toBe(true);
    if (converted.ok) expect(converted.project.extraction.format).toBe(format);
  });

  it('extracts and normalizes a standalone CEF event, never silently stripping extension values', () => {
    const draft = createDraft();
    draft.format = 'cef';
    const result = preview(cef, draft);
    expect(result.counts).toMatchObject({ total: 1, matched: 1, normalized: 1, failures: 0 });
    expect(result.events[0].fields).toMatchObject({
      cef_device_vendor: 'Acme', cef_name: 'Denied',
      action: 'deny', src_ip: '198.51.100.10', dst_port: '443',
    });
  });

  it('rejects malformed CEF/LEEF structures and unsupported mixed headers in local preview', () => {
    const draft = createDraft();
    draft.format = 'cef';
    expect(extractFields('CEF:0|short|header', 'cef', draft).errors.length).toBeGreaterThan(0);
    expect(extractFields('CEF:0|a|b|c|d|e|f|broken', 'cef', draft).errors.length).toBeGreaterThan(0);
    draft.format = 'leef';
    expect(extractFields('LEEF:9.9|a|b|c|d|x=1', 'leef', draft).errors.length).toBeGreaterThan(0);
    expect(extractFields('LEEF:1.0|a|b|c|d|broken', 'leef', draft).errors.length).toBeGreaterThan(0);
  });
});
