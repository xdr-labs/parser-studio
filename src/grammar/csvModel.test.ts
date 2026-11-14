import { describe, expect, it } from 'vitest';
import { extractFields } from '../parser';
import { createDraft } from '../model';
import { generateCsvCases } from './csvModel';

const row = (raw: string, columns: number, delimiter: ',' | ';' | '\t' = ',') =>
  extractFields(raw, 'csv', { ...createDraft(), format: 'csv', csvColumns: Array.from({ length: columns }, (_unused, at) => 'c' + at).join(','), csvDelimiter: delimiter });

describe('delimiter-separated rows', () => {
  it('reads the RFC 4180 examples', () => {
    expect(row('aaa,bbb,ccc', 3).fields).toEqual({ c0: 'aaa', c1: 'bbb', c2: 'ccc' });
    expect(row('"aaa","b,bb","ccc"', 3).fields).toEqual({ c0: 'aaa', c1: 'b,bb', c2: 'ccc' });
    expect(row('"aaa","b""bb","ccc"', 3).fields).toEqual({ c0: 'aaa', c1: 'b"bb', c2: 'ccc' });
    expect(row('aaa,b b,ccc', 3).fields).toEqual({ c0: 'aaa', c1: 'b b', c2: 'ccc' });
  });

  it('declines what RFC 4180 does not allow', () => {
    for (const raw of ['aaa,b"bb,ccc', 'aaa,"bbb,ccc', 'aaa,"bb"b,ccc', 'aaa,bbb', 'aaa,bbb,ccc,ddd'])
      expect(row(raw, 3).errors.length, raw).toBeGreaterThan(0);
  });

  it('meets every model expectation for comma, semicolon and TAB', () => {
    for (const item of generateCsvCases(240, 20261115)) {
      const out = row(item.raw, item.columns, item.delimiter);
      if (item.expect.status === 'UNKNOWN') { expect(out.errors.length, item.id + ' ' + JSON.stringify(item.raw)).toBeGreaterThan(0); continue; }
      expect(out.errors, item.id + ' ' + JSON.stringify(item.raw)).toEqual([]);
      item.expect.values!.forEach((want, index) => {
        const got = out.fields['c' + index];
        if (want === '') expect(got === '' || got === null, `${item.id} field ${index}`).toBe(true);
        else expect(got, `${item.id} field ${index}`).toBe(want);
      });
    }
  });
});
