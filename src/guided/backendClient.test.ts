import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, webcrypto } from 'node:crypto';
import { createDraft, DEMO_SAMPLES } from '../model';
import { toBackendProject } from './backendAdapter';
import { generateBackendPair, validateBackendProject } from './backendClient';

function project() {
  const draft = createDraft();
  draft.format = 'json';
  const result = toBackendProject(draft);
  if (!result.ok) throw new Error(result.issues.map((issue) => issue.message).join(', '));
  return result.project;
}
function fake(status: number, payload: unknown): Response {
  return { status, json: async () => payload } as Response;
}
function sha(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
function pairPayload(slug: string) {
  const names = ['customized_' + slug + '.conf', 'customized_' + slug];
  const sources = ['<source>\n  @type udp\n</source>\n', '# ruby snippet\ndef parse(text)\n  yield nil, {}\nend\n'];
  const files = names.map((name, i) => ({
    name,
    content: sources[i],
    sha256: sha(sources[i]),
    bytes: Buffer.byteLength(sources[i], 'utf8'),
  }));
  return {
    contract: 'host-customized-pair.v0.1',
    files,
    manifest: {
      status: 'DRAFT',
      contract: 'host-customized-pair.v0.1',
      schemaRevision: '0.1',
      engineVerified: false,
      targetImportVerified: false,
      fileHashes: Object.fromEntries(files.map((item) => [item.name, item.sha256])),
      warnings: ['Native runtime compatibility NOT VERIFIED'],
    },
  };
}

describe('same-origin, no-raw-data backend validate/generate client', () => {
  beforeEach(() => vi.stubGlobal('crypto', webcrypto));
  afterEach(() => vi.unstubAllGlobals());

  it('posts configuration-only JSON to the same-origin /validate API explicitly', async () => {
    const mock = vi.fn(async () => fake(200, { ok: true, issues: [] })) as unknown as typeof fetch;
    const result = await validateBackendProject(project(), mock);
    expect(result).toEqual({ ok: true, issues: [] });
    const [url, options] = (mock as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/validate');
    expect(options.credentials).toBe('same-origin');
    expect(options.method).toBe('POST');
    expect(options.headers['Content-Type']).toBe('application/json');
    expect(options.body).not.toContain('198.51.100.10');
    expect(options.body).not.toContain(DEMO_SAMPLES);
  });

  it('preserves field-level backend validation failures with HTTP 422', async () => {
    const issues = [{ code: 'unmapped_classification_field', path: '/classification/rules', message: 'Normalized field unavailable' }];
    const mock = vi.fn(async () => fake(422, { ok: false, issues })) as unknown as typeof fetch;
    expect(await validateBackendProject(project(), mock)).toEqual({ ok: false, issues });
  });

  it('rejects malformed and contradictory validation responses', async () => {
    await expect(validateBackendProject(project(), vi.fn(async () => fake(200, {})) as unknown as typeof fetch)).rejects.toThrow('required properties');
    await expect(validateBackendProject(project(), vi.fn(async () => fake(422, { ok: true, issues: [] })) as unknown as typeof fetch)).rejects.toThrow('conflicts');
  });

  it('only accepts exact matching conf/extensionless files with SHA-256 and DRAFT evidence', async () => {
    const p = project();
    const payload = pairPayload(p.slug);
    const mock = vi.fn(async () => fake(200, payload)) as unknown as typeof fetch;
    const generated = await generateBackendPair(p, mock);
    expect(generated.files.map((item) => item.name)).toEqual(['customized_demo_firewall.conf', 'customized_demo_firewall']);
    expect(generated.manifest.engineVerified).toBe(false);
    expect(generated.manifest.targetImportVerified).toBe(false);
    expect((mock as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0]).toBe('/api/v1/parser-pairs/generate');
  });

  it('never enables download for tampered file content, hash, name or green-washed manifest', async () => {
    const p = project();
    const altered = pairPayload(p.slug);
    altered.files[1].content += 'tampering';
    await expect(generateBackendPair(p, vi.fn(async () => fake(200, altered)) as unknown as typeof fetch)).rejects.toThrow('SHA-256');

    const wrongName = pairPayload(p.slug);
    wrongName.files[1].name = '../out-of-path';
    await expect(generateBackendPair(p, vi.fn(async () => fake(200, wrongName)) as unknown as typeof fetch)).rejects.toThrow('name');

    const unqualified = pairPayload(p.slug);
    (unqualified.manifest as { engineVerified: boolean }).engineVerified = true;
    await expect(generateBackendPair(p, vi.fn(async () => fake(200, unqualified)) as unknown as typeof fetch)).rejects.toThrow('verification status');
  });

  it('never considers an unreachable or non-JSON backend a successful validation', async () => {
    const unreachable = vi.fn(async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch;
    await expect(validateBackendProject(project(), unreachable)).rejects.toThrow('ECONNREFUSED');
    const html = vi.fn(async () => ({ status: 500, json: async () => { throw new Error('not JSON'); } })) as unknown as typeof fetch;
    await expect(validateBackendProject(project(), html)).rejects.toThrow('valid JSON');
  });
});
