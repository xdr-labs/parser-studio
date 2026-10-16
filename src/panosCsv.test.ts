import {describe,expect,it} from 'vitest';
import {extractGenericStructural,panosCsvValues} from './genericStructural';

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

  it('preserves a brace-delimited PAN-OS tail field through Generic Structural',()=>{
    const values=Array.from({length:53},()=> '');
    values[0]='1';values[1]='2026/10/15 00:03:21';values[2]='012345678901';
    values[3]='TRAFFIC';values[6]='2026/10/15 00:03:20';
    values[7]='10.0.0.1';values[8]='8.8.8.8';values[9]='203.0.113.10';values[10]='8.8.8.8';
    values[21]='2026/10/15 00:03:21';
    values[24]='51234';values[25]='443';values[26]='45001';values[27]='443';
    values[29]='tcp';values[30]='allow';values[35]='2026/10/15 00:02:55';
    values[38]='123';values[39]='0x0';values[51]='PA-FW01';values[52]='from-policy';
    const composite='{link-a,tag-a,type-a,ethernet1/1,stamp,100,100,,N/A}';
    const raw='<14>Oct 15 00:03:21 PA-FW01 '+values.join(',')+','+composite;
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    const generic=result.fields.generic as {mode?:string;fields?:Record<string,string>};
    expect(generic.mode).toBe('panos_traffic_csv');
    expect(generic.fields?.vendor_extra_001).toBe(composite);
    expect(generic.fields?.vendor_extra_002).toBeUndefined();
  });
});
