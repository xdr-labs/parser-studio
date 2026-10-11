import { describe, expect, it, vi } from 'vitest';
import { createDraft } from '../model';
import { toBackendProject } from './backendAdapter';
import { fetchBackendCapabilities, assertBackendProjectSupported } from './backendCapabilities';

const capabilities = {
  contract: 'host-customized-pair.v0.1',
  projectSchemaRevision: '0.1',
  authoring: {
    receiverProtocols: ['udp', 'tcp'],
    extractionFormats: ['json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef'],
    httpReceiver: false, multipleDistinctReceiverPorts: false, formatCoverage: 'reviewed-bounded-subset',
    multiline: false, arbitraryRuby: false,
  },
  import: { exactInternalPairsEditable: true, unknownLegacyRubyEditable: false, structuralInspectionOnly: true },
  verification: { engineVerified: false, targetImportVerified: false, liveListenerVerified: false, proprietaryLoaderVerified: false },
  limits: { maxProjectBodyBytes: 262144, maxInspectBodyBytes: 2097152 },
};
function csvProject() {
  const draft = createDraft(); draft.format = 'csv'; draft.csvColumns = 'action,src_ip,dst_port';
  const result = toBackendProject(draft);
  if (!result.ok) throw new Error('CSV adapter failed');
  return result.project;
}
function response(status: number, payload: unknown): Response {
  return { status, json: async () => payload } as Response;
}
describe('read-only backend capabilities (never native target approval)', () => {
  it('GETs same-origin metadata only and approves advertised CSV', async () => {
    const request = vi.fn(async () => response(200, capabilities)) as unknown as typeof fetch;
    const result = await fetchBackendCapabilities(request);
    expect(() => assertBackendProjectSupported(csvProject(), result)).not.toThrow();
    const [url, init] = (request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/capabilities');
    expect(init.method).toBe('GET');
    expect(init.credentials).toBe('same-origin');
    expect(init.cache).toBe('no-store');
    expect(init.body).toBeUndefined();
  });
  it('keeps CSV locked if backend advertises only JSON/KV', async () => {
    const request = vi.fn(async () => response(200, {
      ...capabilities, authoring: { ...capabilities.authoring, extractionFormats: ['json', 'kv'] },
    })) as unknown as typeof fetch;
    const result = await fetchBackendCapabilities(request);
    expect(() => assertBackendProjectSupported(csvProject(), result)).toThrow(/CSV|csv/);
  });
  it.each([
    { ...capabilities, projectSchemaRevision: '0.2' },
    { ...capabilities, authoring: { ...capabilities.authoring, extractionFormats: ['json', 'unknown'] } },
    { ...capabilities, authoring: { ...capabilities.authoring, multiline: true } },
    { ...capabilities, verification: { ...capabilities.verification, targetImportVerified: true } },
    { ...capabilities, import: { ...capabilities.import, unknownLegacyRubyEditable: true } },
  ])('rejects unreviewed or upgraded capability claims', async (broken) => {
    const request = vi.fn(async () => response(200, broken)) as unknown as typeof fetch;
    await expect(fetchBackendCapabilities(request)).rejects.toThrow();
  });
  it('rejects unavailable and non-json capability API', async () => {
    await expect(fetchBackendCapabilities(vi.fn(async () => response(404, {})) as unknown as typeof fetch)).rejects.toThrow();
    await expect(fetchBackendCapabilities(vi.fn(async () => ({ status:200, json:async () => { throw Error('bad'); } })) as unknown as typeof fetch)).rejects.toThrow();
  });
});
