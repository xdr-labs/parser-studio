import { describe, expect, it } from 'vitest';
import { extractFields } from '../parser';
import { createDraft } from '../model';
import { generateJsonCases } from './jsonModel';

const parse = (raw: string) => extractFields(raw, 'json', { ...createDraft(), format: 'json' });
const at = (value: unknown, path: string): unknown =>
  path.split('.').reduce<unknown>((node, key) => (node !== null && typeof node === 'object' ? (node as Record<string, unknown>)[key] : undefined), value);

describe('JSON object events', () => {
  it('reads every spelling RFC 8259 defines as the same value', () => {
    expect(parse('{"s":"\\u0041\\u00e9 \\ud83d\\ude00 a\\/b \\\\ \\"q\\" \\n","t":true,"n":null}').fields)
      .toEqual({ s: 'Aé 😀 a/b \\ "q" \n', t: true, n: null });
    expect(parse('{ "a" : 1e3 ,\t"b" : "x y" }').fields).toEqual({ a: 1000, b: 'x y' });
  });

  it('declines what RFC 8259 does not allow, a repeated name and an integer it cannot hold exactly', () => {
    for (const raw of ['{"a":1,}', "{'a':1}", '{a:1}', '{"a":1', '{"a":1} x', '{"a":01}', '{"a":NaN}', '{"a":1,"a":2}', '{"big":12345678901234567890}'])
      expect(parse(raw).errors.length, raw).toBeGreaterThan(0);
  });

  it('meets every model expectation', () => {
    for (const item of generateJsonCases(120, 20261115)) {
      const out = parse(item.raw);
      if (item.expect.status === 'UNKNOWN') { expect(out.errors.length, item.id + ' ' + item.raw).toBeGreaterThan(0); continue; }
      if (item.expect.neverWrong && out.errors.length) continue;
      expect(out.errors, item.id + ' ' + item.raw).toEqual([]);
      for (const [path, want] of Object.entries(item.expect.values ?? {})) expect(at(out.fields, path), `${item.id} ${path}`).toEqual(want);
    }
  });
});
