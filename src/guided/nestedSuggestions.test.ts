import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { suggestUnmappedFields } from './fieldMappingSuggestions';
import { listSafeLeafPaths } from '../fieldPaths';

describe('nondeveloper nested source path discovery from local JSON events', () => {
  it('offers leaf paths rather than uneditable object-valued parent fields', () => {
    const paths = listSafeLeafPaths({
      http: { request: { method: 'GET', uri: '/synthetic' } },
      action: 'allow', array: [{ token: 'not-supported' }],
    });
    expect(paths).toEqual(['http.request.method', 'http.request.uri', 'action']);
    const draft = createDraft(); draft.format = 'json';
    expect(suggestUnmappedFields([{http:{request:{method:'GET'}}}], draft)).toEqual([{
      source: 'http.request.method', target: 'method', type: 'string', group: 'vendor_fields',
    }]);
  });

  it('does not propose dangerous nested field names or any raw sample values', () => {
    const result = listSafeLeafPaths(JSON.parse('{"obj":{"__proto__":{"secret":"sensitive"},"safe_name":"test"},"constructor":{"token":"untrusted"}}'));
    expect(result).toEqual(['obj.safe_name']);
    expect(JSON.stringify(result)).not.toContain('sensitive');
    expect(JSON.stringify(result)).not.toContain('untrusted');
  });
});
