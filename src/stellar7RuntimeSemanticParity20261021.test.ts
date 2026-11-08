import {describe,expect,it} from 'vitest';
import {createDraft} from './model';
import {preview} from './parser';
import {defaultGuidedOptions} from './guided/contract';
import {valueFitsNormalizationTarget} from './guided/normalizationCandidates';

const reviewed=(source:string,target:string,type:'integer'|'string')=>{
  const draft=createDraft();
  draft.format='json';
  draft.mappings=[{id:'explicit-reviewed',source,target,type}];
  draft.guided={...defaultGuidedOptions(),groups:{'explicit-reviewed':'top_fields'}};
  return draft;
};

// Source grammar/type success is not evidence that a value obeys the
// selected Stellar 7.0 destination's stricter meaning.
describe('actual Browser normalization matches 7.0 candidate value constraints',()=>{
  for(const [source,target,type,invalid,valid] of [
    ['dst_port','dstport','integer',65536,65535],
    ['src_port','srcport','integer',-1,0],
    ['level','severity','integer',101,100],
    ['digest','sha256','string','f'.repeat(32),'f'.repeat(64)],
    ['digest','file.hash.md5','string','f'.repeat(40),'f'.repeat(32)],
    ['action','action','string',200,'block'],
  ] as const){
    it(`rejects semantically invalid ${target} after user explicitly selects an official mapping`,()=>{
      const draft=reviewed(source,target,type);
      expect(valueFitsNormalizationTarget(target,type,invalid)).toBe(false);
      const result=preview(JSON.stringify({[source]:invalid}),draft);
      expect(result.events).toHaveLength(1);
      expect(result.events[0]?.matched).toBe(true);
      expect(result.events[0]?.normalizedOk).toBe(false);
      expect(result.events[0]?.diagnostics).toEqual(expect.arrayContaining([
        expect.objectContaining({stage:'normalize',severity:'error',code:'TYPE_ERROR',field:source}),
      ]));
      expect(result.events[0]?.normalized).not.toHaveProperty(target);
      expect(result.events[0]?.raw).toBe(JSON.stringify({[source]:invalid}));

      const accepted=preview(JSON.stringify({[source]:valid}),draft);
      expect(accepted.events[0]?.normalizedOk).toBe(true);
      expect(accepted.events[0]?.normalized).toHaveProperty(target);
    });
  }

  it('does not impose official hash/port semantics on preserved vendor-local fields',()=>{
    const draft=reviewed('digest','sha256','string');
    draft.guided!.groups['explicit-reviewed']='vendor_fields';
    const result=preview('{"digest":"short"}',draft);
    expect(result.events[0]?.normalizedOk).toBe(true);
    expect(result.events[0]?.normalized).toHaveProperty('Demo Local Draft.sha256','short');
  });
});
