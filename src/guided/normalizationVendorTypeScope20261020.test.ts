import {describe,it,expect} from 'vitest';
import type {MappingRule,SuiteResult} from '../model';
import {validateNormalizationMappings} from './normalizationValidation';

const events=(values:unknown[])=>({
  events:values.map(value=>({fields:{severity:value,srcport:value}})),
} as unknown as SuiteResult);

describe('official field constraints must never govern an unapproved vendor-local mapping',()=>{
  it('preserves categorical source severity strings under vendor namespace without false numeric errors',()=>{
    const mapping:MappingRule={id:'vendor-severity',source:'severity',target:'severity',type:'string'};
    const result=validateNormalizationMappings(events(['medium','high','low']),[mapping],{'vendor-severity':'vendor_fields'});
    expect(result).toEqual([]);
  });

  it('keeps a vendor-local port-like field as text even outside official TCP port ranges',()=>{
    const mapping:MappingRule={id:'vendor-port',source:'srcport',target:'srcport',type:'string'};
    const result=validateNormalizationMappings(events(['out-of-range','70000','not-reported']),[mapping],{'vendor-port':'vendor_fields'});
    expect(result).toEqual([]);
  });

  it('does not disable ordinary chosen value-type checks for vendor fields',()=>{
    const mapping:MappingRule={id:'vendor-severity',source:'severity',target:'severity',type:'integer'};
    const result=validateNormalizationMappings(events(['medium','high']),[mapping],{'vendor-severity':'vendor_fields'});
    expect(result).toEqual([
      {code:'TYPE_ERROR',source:'severity',target:'severity',event:1},
      {code:'TYPE_ERROR',source:'severity',target:'severity',event:2},
    ]);
  });

  it('continues rejecting qualitative values for an explicitly approved official severity mapping',()=>{
    const mapping:MappingRule={id:'official-severity',source:'severity',target:'severity',type:'integer'};
    const result=validateNormalizationMappings(events(['medium','70','101']),[mapping],{'official-severity':'top_fields'});
    expect(result).toEqual([
      {code:'TYPE_ERROR',source:'severity',target:'severity',event:1},
      {code:'TYPE_ERROR',source:'severity',target:'severity',event:3},
    ]);
  });

  it('retains exact official range checks and safe numeric severity values',()=>{
    const mapping:MappingRule={id:'official-severity',source:'severity',target:'severity',type:'integer'};
    expect(validateNormalizationMappings(events([0,35,'100']),[mapping],{'official-severity':'top_fields'})).toEqual([]);
  });

  it('does not add unsafe hidden semantic casts to a generic custom target',()=>{
    const mapping:MappingRule={id:'vendor-severity',source:'severity',target:'severity_text',type:'string'};
    expect(validateNormalizationMappings(events(['medium','high','low']),[mapping],{'vendor-severity':'vendor_fields'})).toEqual([]);
  });
});
