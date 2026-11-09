import {describe,expect,it} from 'vitest';
import type {MappingRule,SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

function scan(records:Record<string,unknown>[],existing:MappingRule[]=[],
  options:{skipAmbiguousTargets?:boolean}={}){
  const suite={events:records.map(fields=>({fields}))} as unknown as SuiteResult;
  return suggestNormalizationCandidatesFromSuite(suite,existing,{},options);
}

describe('MCV2 independent semantic source->Stellar target oracles',()=>{
  const independentCases=[
    {name:'original IP',fields:{src_ip:'192.0.2.4'},path:'src_ip',target:'srcip',high:true},
    {name:'invalid IP',fields:{src_ip:'not-ip'},path:'src_ip',target:'srcip',high:false},
    {name:'Juniper named source port including ICMP',
      fields:{'source-port':'594',proto:1},path:'source-port',target:'srcport',high:true},
    {name:'original destination port',
      fields:{'destination-port':'10400'},path:'destination-port',target:'dstport',high:true},
    {name:'invalid port range',
      fields:{'source-port':65536},path:'source-port',target:'srcport',high:false},
    {name:'documented action',fields:{action:'allow'},path:'action',target:'action',high:true},
    {name:'oversized protocol number',fields:{proto:256},path:'proto',target:'proto',high:false},
    {name:'documented protocol number',fields:{proto:6},path:'proto',target:'proto',high:true},
    {name:'milliseconds duration',fields:{duration_ms:1000},path:'duration_ms',target:'duration',high:true},
  ];
  it.each(independentCases)('$name has exact typed evidence, not a vendor prefix',row=>{
    const found=scan([row.fields]).find(c=>c.source===row.path);
    expect(found?.target).toBe(row.target);
    expect(found?.confidence).toBe(row.high?'HIGH':'REVIEW');
    expect(found?.safeForBulk).toBe(row.high);
    expect(found?.catalogVerified).toBe(true);
  });
  it.each([
    ['post_nat.source-port',{post_nat:{'source-port':594}}],
    ['nat_source.source-port',{nat_source:{'source-port':594}}],
    ['translated_source.source-port',{translated_source:{'source-port':594}}],
    ['postNat.source-port',{postNat:{'source-port':594}}],
    ['session.event_type',{session:{event_type:'threat'}}],
    ['duration',{duration:1000}],
    ['action',{action:'admin-login'}],
    ['syslog.severity',{syslog:{severity:5}}],
  ] as Array<[string,Record<string,unknown>]>)(
    'does not silently promote misleading source meaning %s', (source,fields)=>{
      expect(scan([fields]).some(c=>c.source===source)).toBe(false);
    });
  it('does not bulk-promote ambiguous aliases for one official destination',()=>{
    const records=[{src_ip:'192.0.2.1',source_ip:'198.51.100.2'}];
    const all=scan(records).filter(c=>c.target==='srcip');
    expect(all.map(c=>c.source).sort()).toEqual(['source_ip','src_ip']);
    expect(all.every(c=>c.confidence==='REVIEW'&&!c.safeForBulk)).toBe(true);
    expect(scan(records,[],{skipAmbiguousTargets:true}).some(c=>c.target==='srcip')).toBe(false);
  });
  it('does not turn a sparse multi-event source into bulk approval',()=>{
    const records=[{src_ip:'192.0.2.1'},{dst_ip:'198.51.100.2'}];
    expect(scan(records).filter(c=>['srcip','dstip'].includes(c.target))
      .every(c=>c.confidence==='REVIEW'&&!c.safeForBulk)).toBe(true);
  });
  it('treats a port abbreviation with nontransport protocol as review-only',()=>{
    const result=scan([{sport:443,protocol:'icmp'}]).find(c=>c.source==='sport');
    expect(result).toMatchObject({target:'srcport',confidence:'REVIEW',safeForBulk:false});
  });
  it('preserves a manually edited target, regardless of auto-like ID',()=>{
    const existing:MappingRule={id:'auto-1',source:'src_ip',target:'custom.source',type:'string',
      authoring:{version:1,origin:'USER_EDITED'}};
    const candidate=scan([{src_ip:'192.0.2.1'}],[existing])[0];
    expect(candidate).toMatchObject({target:'srcip',safeForBulk:false,
      replacesMappingId:'auto-1',currentTarget:'custom.source'});
  });
  it('rejects an empty or unknown source set rather than inventing candidates',()=>{
    expect(scan([])).toEqual([]);
    expect(scan([{nonexistent_vendor_key:'suricata'}])).toEqual([]);
  });
});
