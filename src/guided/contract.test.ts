import { describe, expect, it } from 'vitest';
import { createDraft, DEMO_SAMPLES } from '../model';
import { compilerDraftContract, defaultGuidedOptions, plannedPairNames } from './contract';

describe('six-step guided builder UI-to-backend configuration boundary', () => {
  it('requires an explicit supported parser family but never claims native compatibility', () => {
    const draft = createDraft();
    const result = compilerDraftContract(draft);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toContain('explicit JSON or Key / Value');
    expect(result.diagnostics.join(' ')).toContain('backend compiler');
  });

  it('produces typed, ordered normalized groups and branch classifications without source sample logs', () => {
    const draft = { ...createDraft(), format: 'json' as const };
    draft.mappings.push({ id: 'when', source: 'event_time', target: 'custom.event_time', type: 'timestamp' });
    draft.guided = { ...defaultGuidedOptions(), groups: { ...defaultGuidedOptions().groups, when: 'top_fields' } };
    const result = compilerDraftContract(draft);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.project.receiver.protocols).toEqual(['udp', 'tcp']);
    expect(result.project.classification.rules[0].index).toBe('Threat');
    expect(result.project.normalization.top_fields).toEqual([
      { source: 'src_ip', normalized_name: 'custom.source_ip', data_type: 'ip' },
      { source: 'action', normalized_name: 'custom.action', data_type: 'string' },
      { source: 'event_time', normalized_name: 'custom.event_time', data_type: 'date', time_format: 'iso8601', timezone: 'UTC' },
    ]);
    expect(result.project.normalization.ns_fields[0].data_type).toBe('port');
    expect(JSON.stringify(result.project)).not.toContain('198.51.100.10');
    expect(JSON.stringify(result.project)).not.toContain(DEMO_SAMPLES);
    expect(result.project.exportProfile).toBe('host-customized-pair-draft');
  });

  it('rejects unsafe file names, port and duplicate target collisions before handoff', () => {
    const draft = createDraft();
    draft.format = 'kv';
    draft.guided = {
      ...defaultGuidedOptions(), slug: '../outside',
      receiver: { ...defaultGuidedOptions().receiver, port: 22, protocols: [] },
    };
    draft.mappings.push({ id: 'other', source: 'source_ip', target: 'custom.source_ip', type: 'ip' });
    const result = compilerDraftContract(draft);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.join(' ')).toContain('Parser ID');
    expect(result.errors.join(' ')).toContain('Receiving port');
    expect(result.errors.join(' ')).toContain('unique UDP/TCP');
    expect(result.errors.join(' ')).toContain('Duplicate normalized destination');
  });

  it('does not claim a checked active-target port or generated files', () => {
    expect(plannedPairNames('sample_parser')).toEqual({ config: 'customized_sample_parser.conf', parser: 'customized_sample_parser' });
    expect(plannedPairNames('../escape')).toBeNull();
    expect(compilerDraftContract({ ...createDraft(), format: 'json' }).diagnostics)
      .toEqual(expect.arrayContaining([expect.stringContaining('not been connected')]));
  });

  it('rejects unsupported number conversions and repeated route conditions', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings[0].type = 'number';
    const options = defaultGuidedOptions();
    options.classification.rules.push({ id: 'repeat', sourceField: 'action', equals: 'deny', index: 'Session' });
    draft.guided = options;
    const result = compilerDraftContract(draft);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.join(' ')).toContain('does not support type number');
    expect(result.errors.join(' ')).toContain('Duplicate event classification');
  });

  it('uses initial UI configuration for old revisions without guided options', () => {
    const draft = createDraft();
    delete draft.guided;
    draft.format = 'kv';
    const result = compilerDraftContract(draft);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.project.slug).toBe('demo_firewall');
  });
});
