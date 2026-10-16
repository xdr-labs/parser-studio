import {describe,it,expect} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidates,suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

describe('official-catalog normalization candidates',()=>{
  it('recommends documented Stellar destinations with compatible source values',()=>{
    expect(suggestNormalizationCandidates({src_ip:'192.0.2.1',dst_port:443},[])).toEqual([
      expect.objectContaining({source:'src_ip',target:'srcip',type:'ip',confidence:'HIGH',
        catalogVerified:true,catalogRelease:'7.0.xs',group:'top_fields'}),
      expect.objectContaining({source:'dst_port',target:'dstport',type:'integer',confidence:'HIGH',
        catalogVerified:true,catalogRelease:'7.0.xs',group:'top_fields'}),
    ]);
  });
  it('proposes replacing generated custom mappings instead of duplicating their source',()=>{
    const existing=[{id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'string' as const}];
    expect(suggestNormalizationCandidates({src_ip:'192.0.2.1'},existing)).toEqual([
      expect.objectContaining({source:'src_ip',target:'srcip',replacesMappingId:'auto-1',
        currentTarget:'custom.src_ip',safeForBulk:true}),
    ]);
  });
  it('uses whole-sample type evidence and lowers confidence when one value disagrees',()=>{
    const suite={events:[
      {fields:{src_ip:'192.0.2.1'}},{fields:{src_ip:'not-an-ip'}},
    ]} as unknown as SuiteResult;
    expect(suggestNormalizationCandidatesFromSuite(suite,[])[0]).toMatchObject({
      source:'src_ip',confidence:'REVIEW',observed:2,total:2,safeForBulk:false,
    });
  });
  it('covers common AWS CloudTrail and WAF source address names without broad semantic guessing',()=>{
    expect(suggestNormalizationCandidates({sourceIPAddress:'198.51.100.10'},[])[0])
      .toMatchObject({source:'sourceIPAddress',target:'srcip',confidence:'HIGH'});
    expect(suggestNormalizationCandidates({httpRequest:{clientIp:'203.0.113.7'}},[])[0])
      .toMatchObject({source:'httpRequest.clientIp',target:'srcip',confidence:'HIGH'});
  });
  it('covers common CEF/LEEF and camel-case security field names only when values fit',()=>{
    const suggestions=suggestNormalizationCandidates({
      src:'192.0.2.10',dst:'198.51.100.20',spt:'51000',dpt:443,act:'blocked',
      sourceIp:'192.0.2.30',destinationIp:'198.51.100.30',
      sourcePort:52000,destinationPort:'8443',deviceName:'sensor-01',
    },[]);
    expect(suggestions).toEqual(expect.arrayContaining([
      expect.objectContaining({source:'src',target:'srcip',confidence:'HIGH'}),
      expect.objectContaining({source:'dst',target:'dstip',confidence:'HIGH'}),
      expect.objectContaining({source:'spt',target:'srcport',confidence:'HIGH'}),
      expect.objectContaining({source:'dpt',target:'dstport',confidence:'HIGH'}),
      expect.objectContaining({source:'act',target:'action',confidence:'HIGH'}),
      expect.objectContaining({source:'deviceName',target:'hostname',confidence:'HIGH'}),
    ]));
    expect(suggestNormalizationCandidates({src:'not-an-ip'},[])[0])
      .toMatchObject({source:'src',target:'srcip',confidence:'REVIEW',safeForBulk:false});
  });
  it('matches runtime type semantics for IPv6 and timezone-qualified timestamps',()=>{
    expect(suggestNormalizationCandidates({src_ip:'2001:db8::10'},[])[0])
      .toMatchObject({source:'src_ip',target:'srcip',confidence:'HIGH',safeForBulk:true});
    expect(suggestNormalizationCandidates({event_time:'2026-10-16T12:30:00Z'},[])[0])
      .toMatchObject({source:'event_time',target:'timestamp',confidence:'HIGH',safeForBulk:true});
    expect(suggestNormalizationCandidates({event_time:'2026-10-16T12:30:00'},[])[0])
      .toMatchObject({source:'event_time',target:'timestamp',confidence:'REVIEW',safeForBulk:false});
    expect(suggestNormalizationCandidates({dst_port:65536},[])[0])
      .toMatchObject({source:'dst_port',target:'dstport',confidence:'REVIEW',safeForBulk:false});
    expect(suggestNormalizationCandidates({severity:101},[])[0])
      .toMatchObject({source:'severity',target:'severity',confidence:'REVIEW',safeForBulk:false});
    expect(suggestNormalizationCandidates({severity:100},[])[0])
      .toMatchObject({source:'severity',target:'severity',confidence:'HIGH',safeForBulk:true});
  });
  it('abstains when another mapping owns the official destination',()=>{
    expect(suggestNormalizationCandidates({src_ip:'192.0.2.1'},[
      {id:'1',source:'x',target:'srcip',type:'ip'},
    ])).toEqual([]);
  });
});
