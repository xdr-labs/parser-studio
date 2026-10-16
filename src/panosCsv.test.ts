import {describe,expect,it} from 'vitest';
import {panosCsvValues} from './genericStructural';

describe('PAN-OS positional CSV tokenization',()=>{
  it('keeps brace-delimited composite values as one field',()=>{
    expect(panosCsvValues('a,b,{x,y,z},c')).toEqual(['a','b','{x,y,z}','c']);
  });

  it('keeps normal CSV quoting semantics alongside brace groups',()=>{
    expect(panosCsvValues('a,"b,c",{x,y},d')).toEqual(['a','b,c','{x,y}','d']);
  });

  it('fails closed on unbalanced braces or quotes',()=>{
    expect(panosCsvValues('a,{b,c')).toBeNull();
    expect(panosCsvValues('a,"b,c')).toBeNull();
    expect(panosCsvValues('a,b},c')).toBeNull();
  });
});
