/**
 * Owner policy D-1 (decided 2026-11-14): a field written more than once in one event.
 *
 *  - No value is overwritten: the browser never keeps the first or the last value.
 *  - The automatic parser declines the event, in every format that carries named fields.
 *  - The reviewer is told which field is repeated and why the event was declined.
 *  - The event is never reported as completely parsed (parseStatus FULL).
 *
 * The same lines are held to the same policy in the generated Ruby and in the Python source preview by
 * the Semantic Oracle (contracts/semantic-goldens.v1.json, ownerPolicies.D-1).
 */
import { describe, expect, it } from 'vitest';
import { preview } from './parser';
import { createDraft, type ParserDraft } from './model';
import { duplicateFieldMessage, extractStructuredFamily } from './structuredFamilies';

const draft = (patch: Partial<ParserDraft>): ParserDraft => ({ ...createDraft(), ...patch });
const CASES: ReadonlyArray<readonly [string, string, Partial<ParserDraft>, string]> = [
  ['plain key=value', 'srcip=192.0.2.10 dstip=198.51.100.7 srcip=203.0.113.5 action=deny', { format: 'kv' }, 'srcip'],
  ['key=value, same value twice', 'action=deny srcip=192.0.2.10 action=deny', { format: 'kv' }, 'action'],
  ['RFC 3164 with a key=value body', '<134>Nov 14 09:30:00 fw01 srcip=192.0.2.10 dstip=198.51.100.7 srcip=203.0.113.5', { format: 'syslog_rfc3164', syslogBodyFormat: 'kv' }, 'srcip'],
  ['RFC 5424 with a key=value body', '<165>1 2026-11-14T09:30:00Z fw01 app - ID47 - user=alice action=allow user=bob', { format: 'syslog_rfc5424', syslogBodyFormat: 'kv' }, 'user'],
  ['CEF', 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 src=10.0.0.9', { format: 'cef' }, 'src'],
  ['LEEF 1.0', 'LEEF:1.0|Acme|FW|1.0|100|src=10.0.0.1\tdst=2.1.2.2\tsrc=10.0.0.9', { format: 'leef' }, 'src'],
  ['LEEF 2.0', 'LEEF:2.0|Acme|FW|1.0|100|^|usrName=alice^src=10.0.0.1^usrName=bob', { format: 'leef' }, 'usrName'],
];

describe('owner policy D-1: a repeated field is declined, named, and never a complete parse', () => {
  it.each(CASES)('%s', (_name, raw, patch, field) => {
    const suite = preview(raw, draft(patch));
    const event = suite.events[0]!;
    expect(event.parseStatus).not.toBe('FULL');
    expect(event.status).toBe('fail');
    expect(event.extracted).toBe(false);
    expect(suite.counts.failures).toBe(1);
    // The reviewer sees the repeated field and the reason.
    const messages = event.diagnostics.map(item => item.message).join('\n');
    expect(messages).toContain(duplicateFieldMessage(field));
    // Neither the first nor the last value of the repeated field reaches the extracted or the mapped fields.
    expect(event.fields).toEqual({});
    expect(event.normalizedOk).toBe(false);
    expect(event.raw).toBe(raw);
  });

  it('the extractor returns no field at all, so neither the first nor the last value survives', () => {
    const out = extractStructuredFamily('<134>Nov 14 09:30:00 fw01 srcip=192.0.2.10 srcip=203.0.113.5', 'syslog_rfc3164', 'kv');
    expect(out.errors).toEqual([duplicateFieldMessage('srcip')]);
    expect(JSON.stringify(out.fields)).not.toContain('192.0.2.10');
    expect(JSON.stringify(out.fields)).not.toContain('203.0.113.5');
  });

  it('a name that differs only in letter case is a different field (no false rejection)', () => {
    const event = preview('Action=allow action=deny srcip=192.0.2.10', draft({ format: 'kv' })).events[0]!;
    expect(event.diagnostics.map(item => item.message).join('\n')).not.toContain('Duplicate field');
  });
});
