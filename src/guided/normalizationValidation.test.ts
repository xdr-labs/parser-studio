import {expect,it} from 'vitest';
import {validateNormalizationMappings} from './normalizationValidation';
import type {SuiteResult} from '../model';
it('reports unsafe targets, missing sources, type errors and collisions without discarding originals',()=>{
 const suite={events:[{fields:{src_ip:'999.1.1.1',dst_port:443}}]} as unknown as SuiteResult;
 const result=validateNormalizationMappings(suite,[
  {id:'a',source:'src_ip',target:'srcip',type:'ip'},
  {id:'b',source:'dst_port',target:'srcip',type:'port'},
  {id:'c',source:'unknown',target:'custom.unknown',type:'string'},
 ]);
 expect(result.some(x=>x.code==='TYPE_ERROR')).toBe(true);
 expect(result.some(x=>x.code==='TARGET_COLLISION')).toBe(true);
 expect(result.some(x=>x.code==='SOURCE_NOT_FOUND')).toBe(true);
 expect(result.some(x=>x.code==='UNVERIFIED_TARGET')).toBe(true);
});
