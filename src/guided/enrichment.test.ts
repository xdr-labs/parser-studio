import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { preview } from '../parser';
import { defaultGuidedOptions } from './contract';
import { toBackendProject } from './backendAdapter';

describe('no-code safe normalization enrichment', () => {
  it('emits supported ordered operators with no raw customer samples in the backend contract', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.guided = { ...defaultGuidedOptions(), enrichment: [
      { id:'site', operator:'set_const', source:'', target:'custom.site', value:'kr' },
      { id:'lower', operator:'lowercase', source:'custom.action', target:'custom.action_lower', value:'' },
      { id:'copy', operator:'copy', source:'custom.action_lower', target:'custom.action_copy', value:'' },
    ] };
    const result = toBackendProject(draft);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.project.enrichment).toEqual([
      { operator:'set_const', target:'custom.site', value:'kr' },
      { operator:'lowercase', source:'custom.action', target:'custom.action_lower' },
      { operator:'copy', source:'custom.action_lower', target:'custom.action_copy' },
    ]);
    const sample = '{"action":"ALLOW","src_ip":"198.51.100.10","dst_port":443}';
    const parsed = preview(sample, draft);
    expect(parsed.events[0].normalized).toMatchObject({
      'custom.site':'kr', 'custom.action_lower':'allow', 'custom.action_copy':'allow',
    });
    if (result.ok) expect(JSON.stringify(result.project)).not.toContain('198.51.100.10');
  });

  it('refuses destination collision, missing source, prototype segment or case-cast of nontext', () => {
    for (const rule of [
      { id:'a',operator:'set_const',source:'',target:'custom.action',value:'override' },
      { id:'b',operator:'copy',source:'unknown.field',target:'custom.extra',value:'' },
      { id:'c',operator:'set_const',source:'',target:'__proto__.x',value:'unsafe' },
      { id:'d',operator:'lowercase',source:'custom.destination_port',target:'custom.port_lower',value:'' },
    ] as const) {
      const draft = createDraft();
      draft.format = 'json';
      draft.guided = { ...defaultGuidedOptions(), enrichment: [rule] };
      expect(toBackendProject(draft).ok, rule.id).toBe(false);
    }
  });
});
