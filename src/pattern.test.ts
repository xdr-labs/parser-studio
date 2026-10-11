import { describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { createFieldProposal } from './pattern';
import { preview } from './parser';

describe('interactive source-value to editable regex proposal', () => {
  it('generates a named capture and escapes surrounding characters', () => {
    const proposal = createFieldProposal('src=198.51.100.4 action=allow', '198.51.100.4', 'src_ip');
    if ('error' in proposal) throw new Error(proposal.error);
    const result = preview('src=198.51.100.4 action=allow', { ...createDraft(), mappings: [], format: 'regex', pattern: proposal.pattern });
    expect(result.events[0].fields).toEqual({ src_ip: '198.51.100.4' });
    expect(proposal.pattern).toContain('(?<src_ip>\\S+)');
  });

  it('does not silently claim coverage of different event variants', () => {
    const proposal = createFieldProposal('a=1 src=10.0.0.1 end', '10.0.0.1', 'source_ip');
    if ('error' in proposal) throw new Error(proposal.error);
    const result = preview('a=1 src=10.0.0.1 end\na=2 src=10.0.0.2 end', {
      ...createDraft(), mappings: [], format: 'regex', pattern: proposal.pattern,
    });
    expect(result.counts.total).toBe(2);
    expect(result.counts.matched).toBe(1);
  });

  it('rejects invalid field names, ambiguous values and unrelated text', () => {
    expect(createFieldProposal('hi', 'hi', 'bad-name')).toHaveProperty('error');
    expect(createFieldProposal('ip=1 ip=1', '1', 'value')).toHaveProperty('error');
    expect(createFieldProposal('src=abc', 'missing', 'value')).toHaveProperty('error');
    expect(createFieldProposal('hello', 'hello\nworld', 'value')).toHaveProperty('error');
    expect(createFieldProposal('hello', 'hello', 'field')).toHaveProperty('field', 'field');
  });
});
