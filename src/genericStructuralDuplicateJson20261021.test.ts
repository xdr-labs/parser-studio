import {describe,it,expect} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const duplicatePrefixed=[
  'vendor_test {"src_ip":"192.0.2.11","src_ip":"198.51.100.9"}',
  'vendor_test {"user":{"name":"alpha","name":"beta"}}',
  'vendor_test {"\\u0061":1,"a":2}',
  'vendor_test {"batch":[{"id":1,"id":2}]}',
];
const duplicateRfc5424=[
  '<134>1 2026-10-21T00:01:02Z gateway {"a":1,"a":2}',
  '<134>1 2026-10-21T00:01:02Z gateway {"outer":{"name":"one","name":"two"}}',
];
describe('Generic Structural JSON framing preserves every original object member',()=>{
  it.each([...duplicatePrefixed,...duplicateRfc5424])(
    'rejects a structurally recognized JSON wrapper that contains duplicate member names: %s',raw=>{
      const result=extractGenericStructural(raw);
      expect(result.fields).toEqual({});
      expect(result.errors.length).toBeGreaterThan(0);
    }
  );
  it.each([
    'vendor_test {"left":{"k":"one"},"right":{"k":"two"}}',
    'vendor_test {"arr":[{"k":1},{"k":2}]}',
    '<134>1 2026-10-21T00:01:02Z gateway {"left":{"k":"one"},"right":{"k":"two"}}',
  ])('accepts distinct source-member identities in supported JSON wrapper: %s',raw=>{
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).not.toEqual({});
  });
});
