import {describe,expect,it} from 'vitest';
import type {MappingRule,SuiteResult} from '../model';
import {isBlockingNormalizationFinding,reviewNormalizationMappings,validateNormalizationMappings} from './normalizationValidation';
import type {FieldGroup} from './contract';

const otherSources=Array.from({length:40},(_,index)=>'vendor_field_'+String(index).padStart(2,'0'));
const mappings:MappingRule[]=[
  {id:'official-ip',source:'srcip',target:'srcip',type:'ip'},
  ...otherSources.map((source,index)=>({
    id:'vendor-'+index,source,target:source,type:'string' as const,
  })),
];
const groups:Record<string,FieldGroup>={'official-ip':'top_fields'};
for(let i=0;i<otherSources.length;i++)groups['vendor-'+i]='vendor_fields';

function dataset(lateIp:string):SuiteResult{
  const first:Record<string,unknown>={action:'deny',srcip:'192.0.2.1'};
  for(const source of otherSources)first[source]='present';
  return {events:[
    {fields:first},
    ...Array.from({length:8},()=>({fields:{action:'deny'}})),
    {fields:{action:'deny',srcip:lateIp}},
  ]} as unknown as SuiteResult;
}

describe('Issue #217: bounded findings never hide blocking late values',()=>{
  it('reports late invalid official IP after more than 300 nonblocking omissions',()=>{
    const suite=dataset('999.999.999.999');
    const reviewed=reviewNormalizationMappings(suite,mappings,groups);
    expect(reviewed.totalFindings).toBe(1);
    expect(reviewed.totalBlocking).toBe(1);
    expect(reviewed.findings).toHaveLength(1);
    expect(reviewed.findings[0]).toMatchObject({
      code:'TYPE_ERROR',source:'srcip',target:'srcip',event:10,
    });
    expect(validateNormalizationMappings(suite,mappings,groups)
      .some(finding=>isBlockingNormalizationFinding(finding.code))).toBe(true);
  });
  it('accepts optional heterogeneous fields without inventing missing-data warnings',()=>{
    const reviewed=reviewNormalizationMappings(dataset('192.0.2.2'),mappings,groups);
    expect(reviewed.totalFindings).toBe(0);
    expect(reviewed.totalBlocking).toBe(0);
    expect(reviewed.findings).toHaveLength(0);
    expect(reviewed.findings).toEqual([]);
  });
});
