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

// Independent requirements-derived holdout: a nested target overwrites part of
// its parent object, even when no two rules target the identical field name.
it.each([
  ['parent before child', ['custom.actor', 'custom.actor.id']],
  ['child before parent', ['custom.actor.id', 'custom.actor']],
])('flags both hierarchical mapping targets (%s)', (_label, targets) => {
  const suite={events:[{fields:{actor:'alice',actor_id:'123'}}]} as unknown as SuiteResult;
  const mappings=targets.map((target,index)=>({
    id:'actor'+index,source:index===0?'actor':'actor_id',
    target,type:'string' as const,
  }));
  expect(validateNormalizationMappings(suite,mappings)).toEqual(targets.map((target,index)=>({
    code:'TARGET_COLLISION',source:index===0?'actor':'actor_id',target,event:null,
  })));
});

it('permits distinct sibling targets and lexical prefixes without an object-path collision',()=>{
  const suite={events:[{fields:{actor_id:'123',actor_name:'alice',actor_label:'security'}}]} as unknown as SuiteResult;
  expect(validateNormalizationMappings(suite,[
    {id:'id',source:'actor_id',target:'custom.actor.id',type:'string'},
    {id:'name',source:'actor_name',target:'custom.actor.name',type:'string'},
    {id:'label',source:'actor_label',target:'custom.actorId',type:'string'},
  ])).toEqual([]);
});
