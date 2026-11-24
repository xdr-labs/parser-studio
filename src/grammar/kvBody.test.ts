import { describe, expect, it } from 'vitest';
import { parseStrictKeyValues, unescapeKvValue } from './kvBody';
import { generateKvBodyCases } from './kvBodyModel';
import { classifyStructuredParse, independentKeyValuePairs } from './parseStatus';
import { extractStructuredFamily } from '../structuredFamilies';

const pairs = (input: string) => { const body = parseStrictKeyValues(input); return body.ok ? body.pairs : body.reason; };

describe('contract-driven key=value body', () => {
  it('splits pairs at SP and TAB only', () => {
    expect(pairs('a=1  b=2\tc=3 ')).toEqual([['a', '1'], ['b', '2'], ['c', '3']]);
    expect(pairs('a=1\u00a0b=2')).toEqual([['a', '1\u00a0b=2']]);
    expect(pairs('note=a\u2028b action=deny')).toEqual([['note', 'a\u2028b'], ['action', 'deny']]);
  });

  it('reads quoted values whole and decodes only the listed escapes', () => {
    expect(pairs('msg="a=b c" path="C:\\Users\\x" q="say \\"hi\\"" s=\'it is\'')).toEqual(
      [['msg', 'a=b c'], ['path', 'C:\\Users\\x'], ['q', 'say "hi"'], ['s', 'it is']]);
    expect(unescapeKvValue('a\\\\b \\= \\n')).toBe('a\\b = \\n');
  });

  it('keeps an unquoted value exactly as written and decodes only a quoted one', () => {
    const B = '\\';
    expect(pairs('ShareName=' + B + B + '*' + B + 'IPC$ path=' + B + B + 'srv' + B + 'share f=a' + B + '=b u=O' + B + "'Brien d=C:" + B + 'Users' + B + B)).toEqual([
      ['ShareName', B + B + '*' + B + 'IPC$'], ['path', B + B + 'srv' + B + 'share'], ['f', 'a' + B + '=b'], ['u', 'O' + B + "'Brien"], ['d', 'C:' + B + 'Users' + B + B]]);
    expect(pairs('path="' + B + B + B + B + 'srv' + B + B + 'share" f="a' + B + '=b"')).toEqual([['path', B + B + 'srv' + B + 'share'], ['f', 'a=b']]);
  });

  it('reports an unquoted value that was changed on the way as PARTIAL, never FULL', () => {
    const B = '\\';
    const raw = 'ShareName=' + B + B + '*' + B + 'IPC$ action=deny';
    // A reader that decodes the unquoted value loses a backslash; the run-time check must see it.
    expect(classifyStructuredParse(raw, { fields: { ShareName: B + '*' + B + 'IPC$', action: 'deny' }, errors: [] }, 'kv').status).toBe('PARTIAL');
    expect(classifyStructuredParse(raw, { fields: { ShareName: B + B + '*' + B + 'IPC$', action: 'deny' }, errors: [] }, 'kv').status).toBe('FULL');
    const line = '<134>Nov 13 10:00:00 fw01 ' + raw;
    expect(classifyStructuredParse(line, extractStructuredFamily(line, 'syslog_rfc3164', 'kv'), 'kv').status).toBe('FULL');
  });

  it.each([
    ['a=1 a=2', 'DUPLICATE_KEY'], ['a=1 junk b=2', 'MALFORMED_PAIR'],
    ['a="open', 'MALFORMED_PAIR'], ['', 'NO_PAIRS'], ['   ', 'NO_PAIRS'],
  ])('rejects %j as %s', (input, reason) => { expect(pairs(input)).toBe(reason); });

  // G-5 (2026-11-25) supersedes FORBIDDEN_KEY: a reserved name is read under its reversible field name.
  it('reads "__proto__=1" under its reversible field name', () => {
    expect(pairs('__proto__=1')).toEqual([['parserstudio_key___proto__', '1']]);
    expect(pairs('__proto__=1 __proto__=2')).toBe('DUPLICATE_KEY');
  });

  it.each([0x1c, 0x1d, 0x1e, 0x1f])('never reads the information separator U+%s as value data or as a pair separator (issue #214)', (code) => {
    const control = String.fromCharCode(code);
    expect(pairs('srcip=10.1.1.1 action=' + control + 'deny')).toBe('MALFORMED_PAIR');
    expect(pairs('srcip=10.1.1.1' + control + 'action=deny')).toBe('MALFORMED_PAIR');
    expect(pairs('srcip=10.1.1.1 action=de\\' + control + 'ny')).toBe('MALFORMED_PAIR');
    // Inside quotes the sender delimited the value explicitly; the character is kept as written.
    expect(pairs('note="a' + control + 'b"')).toEqual([['note', 'a' + control + 'b']]);
  });

  it('enforces the pair limit from the contract', () => {
    const body = (size: number) => Array.from({ length: size }, (_unused, at) => `f${at}=${at}`).join(' ');
    expect(parseStrictKeyValues(body(100)).ok).toBe(true);
    expect(pairs(body(101))).toBe('TOO_MANY_PAIRS');
  });

  it('meets every model expectation through the product extractor with a FULL verdict only when nothing is lost', () => {
    const cases = generateKvBodyCases(120, 20261114);
    for (const item of cases) {
      const result = extractStructuredFamily(item.raw, 'syslog_rfc3164', 'kv');
      const verdict = classifyStructuredParse(item.raw, result, 'kv');
      if (item.expect.status === 'UNKNOWN') { expect(verdict.status, item.id).toBe('UNKNOWN'); continue; }
      expect(verdict.status, item.id + ' ' + JSON.stringify(item.raw) + ' ' + JSON.stringify(verdict.lostPairs)).toBe('FULL');
      const body = (result.fields.body ?? {}) as Record<string, unknown>;
      for (const [path, want] of Object.entries(item.expect.source ?? {}))
        if (path.startsWith('body.')) expect(body[path.slice(5)], `${item.id} ${path}`).toEqual(want);
    }
  });

  it('keeps the independent tokenizer on both quote kinds, and ends an unquoted value at white space', () => {
    // No backslash rule in the independent reader: a backslash before SP ends the value like any character
    // (audit of 2026-11-15: sharing the grammar's escape rule hid a swallowed pair).
    expect(independentKeyValuePairs("a='x y' b=c\\ d=1 e=\"f g\"").map(pair => [pair.key, pair.rawValue])).toEqual(
      [['a', 'x y'], ['b', 'c\\'], ['d', '1'], ['e', 'f g']]);
  });
});
