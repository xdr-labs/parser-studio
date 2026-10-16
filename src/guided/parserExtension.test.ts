import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {applyMappingExtension,buildMappingExtension} from './parserExtension';

describe('mapping-only parser extension',()=>{
  it('captures mapping additions without rewriting extraction settings',async()=>{
    const base=createDraft();
    const current=structuredClone(base);
    current.mappings.push({id:'new-dst',source:'dst_ip',target:'dstip',type:'ip'});
    current.guided!.groups['new-dst']='top_fields';

    const built=await buildMappingExtension(base,current);
    expect(built.ok).toBe(true);
    if(!built.ok)return;
    expect(built.extension).toMatchObject({
      sourceValuesIncluded:false,extractionChanged:false,
      baseMappingCount:base.mappings.length,
      changes:[{operation:'UPSERT',mappingId:'new-dst',source:'dst_ip',target:'dstip',type:'ip',group:'top_fields'}],
    });
    const applied=await applyMappingExtension(base,built.extension);
    expect(applied).toEqual(current);
  });

  it('allows a reviewed destination/type/group correction on the same source',async()=>{
    const base=createDraft();
    const current=structuredClone(base);
    current.mappings[0]={...current.mappings[0]!,target:'srcip',type:'ip'};
    current.guided!.groups[current.mappings[0]!.id]='top_fields';
    const built=await buildMappingExtension(base,current);
    expect(built.ok).toBe(true);
    if(built.ok)expect(built.extension.changes[0]).toMatchObject({
      source:base.mappings[0]!.source,target:'srcip',group:'top_fields',
    });
  });

  it('rejects extraction changes, mapping removals and source rewrites',async()=>{
    const base=createDraft();
    const extractionChanged=structuredClone(base);extractionChanged.format='json';
    expect(await buildMappingExtension(base,extractionChanged)).toEqual({ok:false,reason:'UNSAFE_BASE_CHANGE'});

    const removed=structuredClone(base);removed.mappings.pop();
    expect(await buildMappingExtension(base,removed)).toEqual({ok:false,reason:'UNSAFE_BASE_CHANGE'});

    const sourceChanged=structuredClone(base);sourceChanged.mappings[0]!.source='other';
    expect(await buildMappingExtension(base,sourceChanged)).toEqual({ok:false,reason:'UNSAFE_BASE_CHANGE'});
  });

  it('rejects tampered extension groups and paths at apply time',async()=>{
    const base=createDraft();
    const current=structuredClone(base);
    current.mappings.push({id:'new-dst',source:'dst_ip',target:'dstip',type:'ip'});
    const built=await buildMappingExtension(base,current);
    expect(built.ok).toBe(true);
    if(!built.ok)return;
    const tampered=structuredClone(built.extension);
    tampered.changes[0]!.group='__proto__';
    expect(await applyMappingExtension(base,tampered)).toBeNull();
    tampered.changes[0]!.group='vendor_fields';
    tampered.changes[0]!.target='bad path';
    expect(await applyMappingExtension(base,tampered)).toBeNull();
  });

  it('rejects applying an extension to the wrong base revision',async()=>{
    const base=createDraft();
    const current=structuredClone(base);
    current.mappings.push({id:'new-dst',source:'dst_ip',target:'dstip',type:'ip'});
    const built=await buildMappingExtension(base,current);
    expect(built.ok).toBe(true);
    if(!built.ok)return;
    const wrong=structuredClone(base);wrong.name='Different product';
    expect(await applyMappingExtension(wrong,built.extension)).toBeNull();
  });

  it('uses the same 60-mapping bound as the parser compiler',async()=>{
    const base=createDraft();
    const oversized=structuredClone(base);
    oversized.mappings=Array.from({length:61},(_,index)=>({
      id:'map-'+index,source:'field_'+index,target:'field_'+index,type:'string' as const,
    }));
    oversized.guided!.groups=Object.fromEntries(
      oversized.mappings.map(mapping=>[mapping.id,'vendor_fields']),
    );
    expect(await buildMappingExtension(base,oversized))
      .toEqual({ok:false,reason:'INVALID_MAPPING_SET'});

    const current=structuredClone(base);
    current.mappings.push({id:'new-dst',source:'dst_ip',target:'dstip',type:'ip'});
    const built=await buildMappingExtension(base,current);
    expect(built.ok).toBe(true);
    if(!built.ok)return;
    const tampered=structuredClone(built.extension);
    tampered.changes=Array.from({length:61},(_,index)=>({
      operation:'UPSERT' as const,mappingId:'extra-'+index,source:'field_'+index,
      target:'field_'+index,type:'string' as const,group:'vendor_fields',
    }));
    expect(await applyMappingExtension(base,tampered)).toBeNull();
  });
});
