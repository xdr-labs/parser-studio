import { describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { createFieldProposal } from './pattern';
import { preview } from './parser';

describe('privacy-first select-value field proposal', () => {
  it('infers a reusable KV field without embedding any original values', () => {
    const proposal = createFieldProposal('src=198.51.100.4 status=ok', '198.51.100.4', 'source_ip');
    if ('error' in proposal) throw new Error(proposal.error);
    expect(proposal.pattern).not.toContain('198.51.100.4');
    expect(proposal.pattern).not.toContain('status=ok');
    const result = preview('src=198.51.100.4 status=ok\nsrc=198.51.100.5 status=denied', {
      ...createDraft(), mappings: [], format: 'regex', pattern: proposal.pattern,
    });
    expect(result.counts.matched).toBe(2);
    expect(result.events[1].fields).toEqual({ source_ip: '198.51.100.5' });
  });

  it('extracts JSON values without persisting other event fields or PII-like literals', () => {
    const raw = '{"timestamp":"2026-10-12T00:00:00Z","device":"DEMO-FW","src_ip":"198.51.100.10","password":"secret-test"}';
    const proposal = createFieldProposal(raw, '198.51.100.10', 'source_ip');
    if ('error' in proposal) throw new Error(proposal.error);
    for (const secret of ['198.51.100.10', 'DEMO-FW', '2026-10-12', 'secret-test']) {
      expect(proposal.pattern).not.toContain(secret);
    }
    const result = preview(raw, { ...createDraft(), mappings: [], format: 'regex', pattern: proposal.pattern });
    expect(result.events[0].fields).toEqual({ source_ip: '198.51.100.10' });
  });

  it('does not silently claim coverage of structurally different event families', () => {
    const proposal = createFieldProposal('{"src":"10.0.0.1"}', '10.0.0.1', 'source_ip');
    if ('error' in proposal) throw new Error(proposal.error);
    const result = preview('{"src":"10.0.0.1"}\nsrc=10.0.0.2', {
      ...createDraft(), mappings: [], format: 'regex', pattern: proposal.pattern,
    });
    expect(result.counts.matched).toBe(1);
    expect(result.counts.total).toBe(2);
  });

  it('rejects ambiguous, partial, unsupported and invalid field input', () => {
    expect(createFieldProposal('src=abc', 'abc', 'bad-name')).toHaveProperty('error');
    expect(createFieldProposal('ip=1 ip=1', '1', 'value')).toHaveProperty('error');
    expect(createFieldProposal('src=abc', 'missing', 'value')).toHaveProperty('error');
    expect(createFieldProposal('hello', 'hello\nworld', 'value')).toHaveProperty('error');
    expect(createFieldProposal('hello world', 'hello', 'value')).toHaveProperty('error');
    expect(createFieldProposal('src=abcdef', 'abc', 'value')).toHaveProperty('error');
    expect(createFieldProposal('src="quoted value"', 'quoted value', 'message')).toHaveProperty('pattern');
  });
});
