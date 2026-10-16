import {expect,it} from 'vitest';
import {validateNormalizationMappings} from './normalizationValidation';
import type {SuiteResult} from '../model';

it('accepts official catalog mappings and reports collisions, source/type errors and unknown targets',()=>{
  const suite={events:[{fields:{src_ip:'999.1.1.1',dst_port:443}}]} as unknown as SuiteResult;
  const result=validateNormalizationMappings(suite,[
    {id:'a',source:'src_ip',target:'srcip',type:'ip'},
    {id:'b',source:'dst_port',target:'srcip',type:'port'},
    {id:'c',source:'unknown',target:'custom.unknown',type:'string'},
    {id:'d',source:'dst_port',target:'not_a_stellar_field',type:'integer'},
  ]);
  expect(result.some(x=>x.code==='TYPE_ERROR')).toBe(true);
  expect(result.some(x=>x.code==='TARGET_COLLISION')).toBe(true);
  expect(result.some(x=>x.code==='SOURCE_NOT_FOUND')).toBe(true);
  expect(result.some(x=>x.code==='UNVERIFIED_TARGET')).toBe(true);
  expect(result.some(x=>x.code==='CATALOG_TYPE_MISMATCH')).toBe(true);
});

it('does not label a type-correct official Stellar mapping as unverified',()=>{
  const suite={events:[{fields:{src_ip:'192.0.2.4',dst_port:443}}]} as unknown as SuiteResult;
  const result=validateNormalizationMappings(suite,[
    {id:'a',source:'src_ip',target:'srcip',type:'ip'},
    {id:'b',source:'dst_port',target:'dstport',type:'integer'},
  ]);
  expect(result).toEqual([]);
});

it('blocks reserved runtime-managed catalog fields',()=>{
  const suite={events:[{fields:{origin:'sensor'}}]} as unknown as SuiteResult;
  expect(validateNormalizationMappings(suite,[
    {id:'a',source:'origin',target:'msg_origin',type:'string'},
  ])).toContainEqual(expect.objectContaining({code:'TARGET_RESERVED',target:'msg_origin'}));
});
