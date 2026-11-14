import { describe, expect, it } from 'vitest';
import { extractStructuredFamily } from '../structuredFamilies';
import { generateCefLeefCases } from './cefLeefModel';

const cef = (extension: string) => extractStructuredFamily('CEF:0|Acme|EDR|1.0|100|File created|5|' + extension, 'cef');

describe('standalone CEF and LEEF', () => {
  it('decodes an escaped backslash in a CEF extension value exactly once (F-11)', () => {
    // On the wire "\\" is one backslash. Decoding twice turned "\\n" into a line feed.
    expect(cef('filePath=C:\\\\Users\\\\new\\\\report.txt act=allowed').fields).toMatchObject({ filePath: 'C:\\Users\\new\\report.txt', act: 'allowed' });
    expect(cef('share=\\\\\\\\server\\\\reports act=allowed').fields).toMatchObject({ share: '\\\\server\\reports', act: 'allowed' });
    // The standard's own example: a value that ends in an escaped backslash, followed by another pair.
    expect(cef('src=10.0.0.1 act=blocked a \\\\ dst=1.1.1.1').fields).toMatchObject({ src: '10.0.0.1', act: 'blocked a \\', dst: '1.1.1.1' });
    expect(cef('msg=line1\\nline2 act=allowed').fields).toMatchObject({ msg: 'line1\nline2' });
  });

  it('still decodes header escapes in the header only', () => {
    const out = extractStructuredFamily('CEF:0|A\\|B|Fire\\\\wall|1.0|100|Name|5|src=10.1.1.1', 'cef');
    expect(out.fields).toMatchObject({ cef_device_vendor: 'A|B', cef_device_product: 'Fire\\wall', src: '10.1.1.1' });
    expect(extractStructuredFamily('CEF:0|Acme|FW|1.0|100|Name\\', 'cef').errors).toHaveLength(1);
  });

  it('keeps LEEF attribute values literal: LEEF has no escape sequences', () => {
    const out = extractStructuredFamily('LEEF:1.0|Acme|FW|1.0|100|share=\\\\server\\reports\tpath=C:\\dir\\\tsrc=10.1.1.1', 'leef');
    expect(out.errors).toEqual([]);
    expect(out.fields).toMatchObject({ share: '\\\\server\\reports', path: 'C:\\dir\\', src: '10.1.1.1' });
  });

  it('treats U+2028 inside a value as value data (F-9)', () => {
    expect(cef('msg=a\u2028b dst=10.2.2.2').fields).toMatchObject({ msg: 'a\u2028b', dst: '10.2.2.2' });
    expect(extractStructuredFamily('LEEF:2.0|Acme|FW|1.0|100|^|msg=a\u2028b^dst=10.2.2.2', 'leef').fields).toMatchObject({ msg: 'a\u2028b', dst: '10.2.2.2' });
  });

  it('meets every model expectation', () => {
    for (const item of generateCefLeefCases(120, 20261115)) {
      const out = extractStructuredFamily(item.raw, item.family);
      if (item.expect.status === 'UNKNOWN') { expect(out.errors.length, item.id).toBeGreaterThan(0); continue; }
      if (out.errors.length && item.expect.neverWrong) continue;
      expect(out.errors, item.id + ' ' + JSON.stringify(item.raw)).toEqual([]);
      for (const [key, want] of Object.entries({ ...item.expect.header, ...item.expect.extension })) expect(out.fields[key], `${item.id} ${key}`).toBe(want);
    }
  });
});
