import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { compilerDraftContract } from './contract';
import { toBackendProject } from './backendAdapter';

describe('no-code field paths match the supported safe backend identifier subset', () => {
  it.each([
    ['source', 'log..level'],
    ['source', 'log.'],
    ['source', 'log.__proto__.value'],
    ['source', 'constructor'],
    ['target', 'custom..action'],
    ['target', 'custom.'],
    ['target', 'msg_origin.src'],
    ['target', 'parser_err_msg.detail'],
  ] as const)('rejects ambiguous or reserved %s path %s at local UI validation', (which, invalid) => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings[0] = { ...draft.mappings[0], [which]: invalid };
    const local = compilerDraftContract(draft);
    expect(local.ok).toBe(false);
    expect(toBackendProject(draft).ok).toBe(false);
  });

  it('detects nested normalized destination conflicts before sending to backend', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings.push({
      id: 'overlap', source: 'source_extra', target: 'custom.source_ip.child', type: 'string',
    });
    const local = compilerDraftContract(draft);
    expect(local.ok).toBe(false);
    if (!local.ok) expect(local.errors.join(' ')).toContain('collision');
    expect(toBackendProject(draft).ok).toBe(false);
  });

  it('accepts valid dotted field paths without relying on a proprietary dictionary', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings.push({
      id: 'nested', source: 'http.request.method', target: 'custom.http_method', type: 'string',
    });
    expect(compilerDraftContract(draft).ok).toBe(true);
    expect(toBackendProject(draft).ok).toBe(true);
  });
});
