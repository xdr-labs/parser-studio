import { createHash, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { inspectParserPair } from './pairInspection';

const input = {
  name: 'customized_demo_fw',
  confContent: '<source>\n @type udp\n port 5514\n</source>\n',
  fragmentContent: '# synthetic no-op\n',
};
const sha = (v: string) => createHash('sha256').update(v).digest('hex');
const response = {
  format: 'host-customized-pair', name: input.name,
  originalHashes: { conf: sha(input.confContent), fragment: sha(input.fragmentContent) },
  receiver: { protocols: ['udp'], ports: [5514], sourceCount: 1 },
  fragment: { markersComplete: false, hasParseEntry: false, opaqueRuby: true },
  importStatus: 'OPAQUE_READ_ONLY', roundTripVerified: false, portableProject: null,
  diagnostics: [{ code: 'PAIR_NOT_REPRODUCIBLE', severity: 'warning', message: 'sensitive text never displayed' }],
  warnings: ['sensitive text never displayed'],
};
const mock = (status: number, data: unknown) => vi.fn(async () => ({
  status, json: async () => data,
})) as unknown as typeof fetch;

describe('explicit-only paired source inspection: provenance not executable', () => {
  beforeEach(() => vi.stubGlobal('crypto', webcrypto));
  afterEach(() => vi.unstubAllGlobals());
  it('sends bounded sources to same origin only when called, returns metadata without raw bodies', async () => {
    const requester = mock(200, response);
    const checked = await inspectParserPair(input, requester);
    expect(checked.importStatus).toBe('OPAQUE_READ_ONLY');
    expect(checked.editable).toBe(false);
    expect(checked.diagnostics).toEqual(['PAIR_NOT_REPRODUCIBLE']);
    expect(JSON.stringify(checked)).not.toContain('sensitive text');
    expect(JSON.stringify(checked)).not.toContain('synthetic no-op');
    const [path, args] = (requester as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(path).toBe('/api/v1/parser-pairs/inspect');
    expect(args.credentials).toBe('same-origin');
    expect(args.method).toBe('POST');
  });
  it('rejects a spoofed hash, guessed editable status or opaque project', async () => {
    await expect(inspectParserPair(input, mock(200, {
      ...response, originalHashes: { ...response.originalHashes, conf: '0'.repeat(64) },
    }))).rejects.toThrow();
    await expect(inspectParserPair(input, mock(200, {
      ...response, importStatus: 'EDITABLE_EXACT', roundTripVerified: true,
    }))).rejects.toThrow();
    await expect(inspectParserPair(input, mock(200, {
      ...response, portableProject: { projectId: 'stolen' },
    }))).rejects.toThrow();
  });
  it('rejects unsafe filename or oversized body without sending a request', async () => {
    const requester = mock(200, response);
    await expect(inspectParserPair({ ...input, name: '../other' }, requester)).rejects.toThrow();
    await expect(inspectParserPair({ ...input, confContent: 'x'.repeat(2097152) }, requester)).rejects.toThrow();
    expect(requester).not.toHaveBeenCalled();
  });
  it('does not treat HTTP validation failure as successful inspection', async () => {
    await expect(inspectParserPair(input, mock(422, {error:'INVALID_PAIR'}))).rejects.toThrow();
  });
});
