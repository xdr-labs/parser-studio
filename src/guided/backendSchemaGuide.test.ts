import { describe, expect, it, vi } from 'vitest';
import { fetchBackendSchemaGuide, parseBackendSchemaGuide } from './backendSchemaGuide';

const input = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'urn:xdr-labs:parser-project:v0.1',
  properties: {
    schemaRevision: { const: '0.1' },
    sourceCategory: { enum: ['network', 'endpoint', 'cloud', 'application', 'other'] },
    extraction: { properties: {
      format: { enum: ['json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef'] },
    } },
    receiver: { properties: {
      protocols: { items: { enum: ['udp', 'tcp'] } },
      port: { type: 'integer', minimum: 1, maximum: 65535 },
      messageLengthLimit: { type: 'integer', minimum: 256, maximum: 65536 },
    } },
  },
  $defs: {
    fieldRule: { properties: { data_type: { enum: ['string','integer','ip','port','boolean','date'] },
      normalized_name: { pattern: String.raw`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$`, maxLength: 128 },
    } },
    mapping: { propertyNames: {
      pattern: String.raw`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$`, maxLength: 128,
    } },
  },
};

const make = (status: number, body: unknown) => vi.fn(async () =>
  ({ status, json: async () => body })) as unknown as typeof fetch;

describe('live same-origin backend JSON Schema guide (not a vendor dictionary)', () => {
  it('projects exact backend v0.1 formatting, types, identifier and size bounds', () => {
    expect(parseBackendSchemaGuide(input)).toEqual({
      revision: '0.1',
      formats: ['json','kv','csv','syslog_rfc5424','cef','leef'],
      fieldTypes: ['string','integer','ip','port','boolean','date'],
      sourceCategories: ['network', 'endpoint', 'cloud', 'application', 'other'],
      receiverProtocols: ['udp','tcp'],
      fieldNamePattern: input.$defs.mapping.propertyNames.pattern,
      fieldNameMaxLength: 128,
      port: { min: 1, max: 65535 },
      messageLength: { min: 256, max: 65536 },
    });
  });

  it('queries only a same-origin GET and never sends sample or mapping values', async () => {
    const requester = make(200, input);
    expect((await fetchBackendSchemaGuide(requester)).fieldTypes).toContain('ip');
    const [path, options] = (requester as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(path).toBe('/api/v1/parser-pairs/schema');
    expect(options).toMatchObject({ method:'GET', cache:'no-store', credentials:'same-origin' });
    expect(options.body).toBeUndefined();
  });

  it.each([
    { $id: 'urn:unknown:schema' },
    { properties: { ...input.properties, schemaRevision: { const: '0.2' } } },
    { properties: { ...input.properties, extraction: { properties: { format: { enum: ['json','shell'] } } } } },
    { $defs: { ...input.$defs, mapping: { propertyNames: { pattern: '.*', maxLength: 1024 } } } },
    { $defs: { ...input.$defs, fieldRule: { properties: {
      ...input.$defs.fieldRule.properties, data_type: {enum: ['string','eval']},
    } } } },
    { properties: { ...input.properties, receiver: { properties: {
      ...input.properties.receiver.properties, port: { type:'integer', minimum: 1, maximum: 999999 },
    } } } },
  ])('refuses unexpected contract/unsafe future schema capabilities', (change) => {
    expect(() => parseBackendSchemaGuide({ ...input, ...change })).toThrow();
  });

  it('rejects missing JSON schema, backend errors, and invalid responses', async () => {
    await expect(fetchBackendSchemaGuide(make(404, {}))).rejects.toThrow('HTTP 404');
    await expect(fetchBackendSchemaGuide(make(200, {}))).rejects.toThrow();
    const invalid = vi.fn(async () => ({ status: 200, json: async () => {throw new Error('html');} })) as unknown as typeof fetch;
    await expect(fetchBackendSchemaGuide(invalid)).rejects.toThrow();
  });
});
