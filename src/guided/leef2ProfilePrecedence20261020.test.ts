import {it,expect} from 'vitest';
import fixture from '../../tests/fixtures/roadmap-leef2-precedence-20261020.json';
import {extractGenericStructural} from '../genericStructural';
import {createDraft} from '../model';
import {lookupFieldValue} from '../fieldPaths';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';

for(const sample of fixture.positive){
  it('selects the complete LEEF profile before a legacy KV approximation: '+sample.name,()=>{
    const expected={leef_header:sample.header,leef_extension:sample.extension,
      generic:{mode:'leef2_implicit_tab',source_raw:sample.raw}};
    expect(extractGenericStructural(sample.raw,'leef2_implicit_tab')).toEqual({fields:expected,errors:[]});
    const prepared=buildAutomaticGenericStructuralDraft(sample.raw,createDraft());
    expect(prepared).not.toBeNull();
    expect(prepared!.draft.genericStructuralProfile).toBe('leef2_implicit_tab');
    expect(prepared!.suite.counts).toMatchObject({total:1,extracted:1,failures:0});
    const event=prepared!.suite.events[0]!;
    expect(event.fields).toEqual(expected);
    for(const mapping of prepared!.draft.mappings.filter(item=>item.type==='string')){
      const vendor=prepared!.draft.guided!.groups[mapping.id]==='vendor_fields';
      const container=vendor?event.normalized[prepared!.draft.vendor] as Record<string,unknown>:event.normalized;
      expect(lookupFieldValue(container,mapping.target)).toEqual(lookupFieldValue(expected,mapping.source));
    }
  });
}

it('keeps explicit V15 behavior while automatic discovery chooses the preserved LEEF field tree',()=>{
  const sample=fixture.positive[0]!;
  const legacy=extractGenericStructural(sample.raw);
  expect(legacy.errors).toEqual([]);
  expect((legacy.fields.generic as {mode:string}).mode).toBe('space_kv');
  expect(legacy.fields).not.toHaveProperty('leef_header');
  expect(extractGenericStructural(sample.raw,'leef2_implicit_tab').fields).toHaveProperty('leef_header',sample.header);
});

for(const sample of fixture.negative){
  it('keeps rejected selected LEEF input out of legacy KV fallback: '+sample.name,()=>{
    expect(extractGenericStructural(sample.raw,'leef2_implicit_tab').errors).not.toHaveLength(0);
    expect(buildAutomaticGenericStructuralDraft(sample.raw,createDraft())).toBeNull();
  });
}
