import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {findStellarMetadataField,STELLAR_METADATA_CATALOG_PROVENANCE} from './stellarMetadataCatalog';
import {suggestNormalizationCandidates,valueFitsNormalizationTarget} from './normalizationCandidates';
import {validateNormalizationMappings} from './normalizationValidation';

describe('fixed Stellar Cyber 7.0 namespace contract, no cross-version fallback',()=>{
  it('exposes only explicitly documented, typed 7.0 nested destinations',()=>{
    expect(STELLAR_METADATA_CATALOG_PROVENANCE.release).toBe('7.0.xs');
    for(const [name,type] of [
      ['host.ip','ip'],['host.name','string'],['user.name','string'],
      ['process.name','string'],['process.pid','integer'],
      ['process.command_line','string'],['process.hash.sha256','string'],
      ['file.name','string'],['file.path','string'],['file.hash.sha256','string'],
    ]){
      expect(findStellarMetadataField(name)).toMatchObject({
        name,mappingType:type,mappable:true,group:'ns_fields',
      });
    }
    expect(findStellarMetadataField('file')).toMatchObject({mappable:false});
    expect(findStellarMetadataField('process')).toMatchObject({mappable:false});
    expect(findStellarMetadataField('unknown.hash.sha256')).toBeUndefined();
  });

  it('validates documented hash meanings rather than string type alone',()=>{
    expect(valueFitsNormalizationTarget('sha256','string','a'.repeat(32))).toBe(false);
    expect(valueFitsNormalizationTarget('sha256','string','a'.repeat(64))).toBe(true);
    expect(valueFitsNormalizationTarget('file.hash.sha256','string','a'.repeat(32))).toBe(false);
    expect(valueFitsNormalizationTarget('process.hash.sha256','string','A'.repeat(64))).toBe(true);
    expect(valueFitsNormalizationTarget('file.hash.sha1','string','a'.repeat(40))).toBe(true);
    expect(valueFitsNormalizationTarget('file.hash.md5','string','x'.repeat(32))).toBe(false);
    expect(valueFitsNormalizationTarget('action','string',200)).toBe(false);
    expect(valueFitsNormalizationTarget('action','string','block')).toBe(true);
  });

  it('proposes only full-sample typed nested 7.0 mappings',()=>{
    const data={
      process:{name:'powershell.exe',pid:890,hash:{sha256:'a'.repeat(64)}},
      file:{hash:{sha256:'b'.repeat(64)}},
      host:{ip:'198.51.100.25'},user:{name:'test.user'},
    };
    const suggestions=suggestNormalizationCandidates(data,[]);
    for(const field of ['process.name','process.pid','process.hash.sha256','file.hash.sha256','host.ip','user.name'])
      expect(suggestions).toContainEqual(expect.objectContaining({source:field,target:field,
        confidence:'HIGH',safeForBulk:true,group:'ns_fields'}));
    const malformed=suggestNormalizationCandidates({file:{hash:{sha256:'a'.repeat(32)}}},[]);
    expect(malformed[0]).toMatchObject({target:'file.hash.sha256',confidence:'REVIEW',safeForBulk:false});
  });

  it('writes reviewed namespace mapping to nested preview while respecting official type',()=>{
    const draft=createDraft();draft.format='json';
    draft.mappings=[
      {id:'proc',source:'process.name',target:'process.name',type:'string'},
      {id:'host',source:'host.ip',target:'host.ip',type:'ip'},
    ];
    draft.guided={...draft.guided!,groups:{...draft.guided!.groups,proc:'ns_fields',host:'ns_fields'}};
    const result=preview(JSON.stringify({process:{name:'powershell.exe'},host:{ip:'192.0.2.9'}}),draft);
    expect(result.events[0]?.normalized).toMatchObject({process:{name:'powershell.exe'},host:{ip:'192.0.2.9'}});
    expect(validateNormalizationMappings(result,draft.mappings,draft.guided.groups)).toEqual([]);
  });
});
