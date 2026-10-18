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
      custom:{site:'kr',action_lower:'allow',action_copy:'allow'},
    });
    if (result.ok) expect(JSON.stringify(result.project)).not.toContain('198.51.100.10');
  });

  it('previews and exports bounded split and merge enrichment with exact field counts', () => {
    const draft=createDraft();draft.format='json';
    draft.mappings=[...draft.mappings,{id:'endpoint',source:'endpoint',target:'custom.endpoint',type:'string'}];
    const base=defaultGuidedOptions();
    draft.guided={...base,groups:{...base.groups,endpoint:'top_fields'},enrichment:[
      {id:'split',operator:'split_field',source:'custom.endpoint',target:'',value:'',delimiter:':',
        targets:['custom.endpoint_host','custom.endpoint_port_text']},
      {id:'merge',operator:'merge_fields',source:'',target:'custom.endpoint_joined',value:'',delimiter:':',
        sources:['custom.endpoint_host','custom.endpoint_port_text']},
    ]};
    const result=toBackendProject(draft);expect(result.ok).toBe(true);
    if(result.ok)expect(result.project.enrichment).toEqual([
      {operator:'split_field',source:'custom.endpoint',delimiter:':',
        targets:['custom.endpoint_host','custom.endpoint_port_text']},
      {operator:'merge_fields',sources:['custom.endpoint_host','custom.endpoint_port_text'],
        delimiter:':',target:'custom.endpoint_joined'},
    ]);
    const parsed=preview('{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"endpoint":"192.0.2.10:8443"}',draft);
    expect(parsed.counts).toMatchObject({total:1,matched:1,extracted:1,normalized:1,failures:0});
    expect(parsed.events[0]?.normalized).toMatchObject({
      custom:{endpoint:'192.0.2.10:8443',endpoint_host:'192.0.2.10',
        endpoint_port_text:'8443',endpoint_joined:'192.0.2.10:8443'},
    });
    const mismatch=preview('{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"endpoint":"no-delimiter"}',draft);
    expect(mismatch.counts.failures).toBe(1);
    expect(mismatch.events[0]?.diagnostics.some(x=>x.code==='ENRICHMENT_TYPE')).toBe(true);
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
