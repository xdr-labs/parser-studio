import { describe, expect, it } from 'vitest';
import { createDraft, DEMO_SAMPLES } from './model';
import { convertValue, detectFormat, extractFields, preview, splitEvents } from './parser';

describe('safe, version-neutral browser preview', () => {
  it('detects known sample formats and declines unknowns', () => {
    expect(detectFormat('{"action":"allow"}').format).toBe('json');
    expect(detectFormat('action=allow ip=198.51.100.10').format).toBe('kv');
    expect(detectFormat('<34>1 2026-10-12T00:00:00Z host app 123 ID47 - msg').format).toBe('syslog');
    expect(detectFormat('one,two,three').format).toBe('csv');
    expect(detectFormat('freeform event').format).toBe('unknown');
  });

  it('retains physical line numbers while rejecting blank events', () => {
    expect(splitEvents('one\n\n  two\r\n')).toEqual([
      { raw: 'one', line: 1 }, { raw: '  two', line: 3 },
    ]);
  });

  it('parses JSON and quoted KV without turning malformed JSON into success', () => {
    const draft = createDraft();
    expect(extractFields('{"ok":true,"port":443}', 'json', draft).fields).toEqual({ ok: true, port: 443 });
    expect(extractFields('host="demo system" action=deny', 'kv', draft).fields).toEqual({ host: 'demo system', action: 'deny' });
    expect(extractFields('{"missing":', 'json', draft).errors).toContain('Invalid JSON object');
  });

  it('parses escaped CSV with explicit column schema and rejects truncated rows', () => {
    const draft = { ...createDraft(), csvColumns: 'action,message' };
    expect(extractFields('deny,"test, quoted ""value"""', 'csv', draft).fields)
      .toEqual({ action: 'deny', message: 'test, quoted "value"' });
    expect(extractFields('deny', 'csv', draft).errors[0]).toContain('column count mismatch');
  });

  it('parses the declared RFC5424 header subset, not arbitrary syslog variants', () => {
    const draft = createDraft();
    const result = extractFields('<34>1 2026-10-12T00:00:00Z host app 123 ID47 - logged in', 'syslog', draft);
    expect(result.fields).toMatchObject({ syslog_priority: 34, host: 'host', message: 'logged in' });
    expect(extractFields('<34>Oct 11 host syslog', 'syslog', draft).errors.length).toBe(1);
  });

  it('can extract named-group regex while rejecting suspicious constructs', () => {
    const draft = { ...createDraft(), pattern: '^action=(?<action>\\w+)$' };
    expect(extractFields('action=allow', 'regex', draft).fields).toEqual({ action: 'allow' });
    expect(extractFields('other value', 'regex', draft).errors).toContain('Expression did not match this event');
    expect(extractFields('aaaa', 'regex', { ...draft, pattern: '(?<x>(a+)+)$' }).errors[0]).toMatch(/unsupported/);
  });

  it('enforces IP, port, timestamp, booleans and strict integers', () => {
    expect(convertValue('198.51.100.11', 'ip').value).toBe('198.51.100.11');
    expect(convertValue('999.1.1.1', 'ip').error).toBeTruthy();
    expect(convertValue('65536', 'port').error).toBeTruthy();
    expect(convertValue('22', 'port').value).toBe(22);
    expect(convertValue('1.5', 'integer').error).toBeTruthy();
    expect(convertValue('FALSE', 'boolean').value).toBe(false);
    expect(convertValue('2026-10-12T00:00:00', 'timestamp').error).toBeTruthy();
    expect(convertValue('2026-10-12T00:00:00+09:00', 'timestamp').value).toBe('2026-10-11T15:00:00.000Z');
  });

  it('reports exact coverage and source fields not silently dropped', () => {
    const suite = preview(DEMO_SAMPLES, createDraft());
    expect(suite.counts).toEqual({ total: 3, matched: 3, extracted: 3, normalized: 2, failures: 1, warnings: 2 });
    expect(suite.events[0].unmapped).toContain('device');
    expect(suite.events[2].diagnostics.filter((x) => x.code === 'TYPE_ERROR')).toHaveLength(2);
    expect(suite.nativeFluentdVerified).toBe(false);
    expect(suite.stellarExportVerified).toBe(false);
  });

  it('shows missing mappings, collisions and bad target field names', () => {
    const draft = createDraft();
    const suite = preview('{"action":"allow","src_ip":"198.51.100.2","dst_port":80}', {
      ...draft,
      mappings: [...draft.mappings, { id: 'dupe', source: 'action', target: 'custom.action', type: 'string' }],
    });
    expect(suite.events[0].diagnostics.some((x) => x.code === 'TARGET_COLLISION')).toBe(true);
    expect(suite.events[0].normalizedOk).toBe(false);
    expect(preview('{"action":"allow"}', { ...draft, mappings: [] }).counts.normalized).toBe(0);
    expect(preview('{"action":"allow"}', { ...draft, mappings: [{ id: 'x', source: 'action', target: 'bad target', type: 'string' }] }).counts.failures).toBe(1);
  });

  it('never claims a zero-event suite or oversized dataset is verified', () => {
    const empty = preview('  \n', createDraft());
    expect(empty.counts).toEqual({ total: 0, matched: 0, extracted: 0, normalized: 0, failures: 0, warnings: 0 });
    expect(empty.nativeFluentdVerified).toBe(false);
    const tooLarge = preview('x'.repeat(65537), createDraft());
    expect(tooLarge.events[0].diagnostics[0].code).toBe('DATASET_TOO_LARGE');
    expect(tooLarge.counts.failures).toBe(1);
  });
});
