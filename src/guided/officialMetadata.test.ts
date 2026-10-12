import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { toBackendProject } from './backendAdapter';
import { curatedOfficialMetadata, applyOfficialMetadataField, officialDictionaryUrl, officialDictionaryUrl65 } from './officialMetadata';

describe('curated factual field names from published Stellar Cyber Metadata Dictionary', () => {
  it('provides a short version-labeled official reference, never a whole proprietary schema', () => {
    expect(officialDictionaryUrl).toBe('https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm');
    expect(officialDictionaryUrl65).toBe('https://docs.stellarcyber.ai/6.5.xs/Common/Metadata-Dictionary.htm');
    expect(curatedOfficialMetadata.length).toBeGreaterThanOrEqual(12);
    expect(curatedOfficialMetadata.length).toBeLessThanOrEqual(25);
    const src = curatedOfficialMetadata.find((field) => field.name === 'srcip');
    const dst = curatedOfficialMetadata.find((field) => field.name === 'dstport');
    const action = curatedOfficialMetadata.find((field) => field.name === 'action');
    expect(src).toMatchObject({ documentedType: 'ip', uiType: 'ip' });
    expect(dst).toMatchObject({ documentedType: 'integer', uiType: 'port' });
    expect(action).toMatchObject({ documentedType: 'string', uiType: 'string' });
    expect(curatedOfficialMetadata.some((field) => field.name === 'msg_origin')).toBe(false);
    expect(curatedOfficialMetadata.map((field) => field.documentedType)).not.toContain('object');
    expect(new Set(curatedOfficialMetadata.map(field => field.name)).size).toBe(curatedOfficialMetadata.length);
  });

  it('applies a chosen standard top-level field without mutating the previous draft', () => {
    const draft = createDraft();
    draft.format = 'json';
    const before = structuredClone(draft);
    const result = applyOfficialMetadataField(draft, 'source-ip', 'srcip');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(draft).toEqual(before);
    expect(result.draft.mappings[0]).toMatchObject({ source:'src_ip',target:'srcip',type:'ip' });
    expect(result.draft.guided?.groups['source-ip']).toBe('top_fields');
    expect(result.draft.mappings[1]).toEqual(draft.mappings[1]);
    const backend = toBackendProject(result.draft);
    expect(backend.ok).toBe(true);
    if (backend.ok) expect(backend.project.normalization.topFields.src_ip)
      .toEqual({normalized_name:'srcip',data_type:'ip'});
  });

  it('maps documented integer port field to the narrower safe backend port validator', () => {
    const draft=createDraft();draft.format='json';
    const result=applyOfficialMetadataField(draft,'target-port','dstport');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.draft.mappings[1]).toMatchObject({target:'dstport',type:'port'});
    expect(result.draft.guided?.groups['target-port']).toBe('top_fields');
  });

  it('rejects collisions, unknown fields, or blank source fields without silent changes', () => {
    const draft=createDraft();draft.format='json';
    draft.mappings[1].target='srcip';
    expect(applyOfficialMetadataField(draft,'source-ip','srcip').ok).toBe(false);
    expect(applyOfficialMetadataField(draft,'source-ip','msg_origin').ok).toBe(false);
    expect(applyOfficialMetadataField(draft,'missing-mapping','srcip').ok).toBe(false);
    draft.mappings[0].source='';
    expect(applyOfficialMetadataField(draft,'source-ip','dstip').ok).toBe(false);
  });
});
