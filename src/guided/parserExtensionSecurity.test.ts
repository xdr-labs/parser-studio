import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {applyMappingExtension,buildMappingExtension} from './parserExtension';

describe('mapping extension bounds',()=>{
  it('rejects a one-change extension that would exceed the total 60-mapping bound',async()=>{
    const base=createDraft();
    base.mappings=Array.from({length:60},(_,index)=>({
      id:'base-'+index,source:'field_'+index,target:'field_'+index,type:'string' as const,
    }));
    base.guided!.groups=Object.fromEntries(
      base.mappings.map(mapping=>[mapping.id,'vendor_fields']),
    );
    const current=structuredClone(base);
    current.mappings[0]={...current.mappings[0]!,target:'field_zero'};
    const built=await buildMappingExtension(base,current);
    expect(built.ok).toBe(true);
    if(!built.ok)return;
    const tampered=structuredClone(built.extension);
    tampered.changes=[{
      operation:'UPSERT',mappingId:'overflow',source:'overflow',target:'overflow',
      type:'string',group:'vendor_fields',
    }];
    expect(await applyMappingExtension(base,tampered)).toBeNull();
  });

  it('rejects duplicate change identifiers in an extension',async()=>{
    const base=createDraft();
    const current=structuredClone(base);
    current.mappings.push({id:'new-dst',source:'dst_ip',target:'dstip',type:'ip'});
    const built=await buildMappingExtension(base,current);
    expect(built.ok).toBe(true);
    if(!built.ok)return;
    const tampered=structuredClone(built.extension);
    tampered.changes=[tampered.changes[0]!,tampered.changes[0]!];
    expect(await applyMappingExtension(base,tampered)).toBeNull();
  });
});
