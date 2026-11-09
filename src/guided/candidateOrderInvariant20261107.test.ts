import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {normalizationCandidateScanStatus,suggestNormalizationCandidatesFromSuite,
  MAX_OFFICIAL_CANDIDATE_SCAN} from './normalizationCandidates';

function suite(fields:Record<string,unknown>[]):SuiteResult{
  return {events:fields.map(value=>({fields:value}))} as unknown as SuiteResult;
}

describe('official candidate scan never samples only the first event family',()=>{
  const vendor:Record<string,unknown>={};
  for(let i=0;i<100;i++)vendor['vendor_field_'+String(i).padStart(3,'0')]='retained';
  const official={srcip:'192.0.2.10',dstip:'198.51.100.11',srcport:51324,dstport:443,proto:6};
  it('preserves the same REVIEW candidates when event order is reversed',()=>{
    const before=suite([vendor,official]),after=suite([official,vendor]);
    const normalize=(s:SuiteResult)=>suggestNormalizationCandidatesFromSuite(s,[])
      .map(c=>({source:c.source,target:c.target,confidence:c.confidence,safeForBulk:c.safeForBulk}))
      .sort((a,b)=>a.source.localeCompare(b.source));
    const first=normalize(before),last=normalize(after);
    expect(first).toEqual(last);
    expect(first.map(c=>c.target).sort()).toEqual(['dstip','dstport','proto','srcip','srcport']);
    expect(first.every(c=>c.confidence==='REVIEW'&&!c.safeForBulk)).toBe(true);
    expect(normalizationCandidateScanStatus(before).eligiblePaths).toBe(5);
  });
  it('finds late official fields without hiding competing aliases after the authoring budget',()=>{
    const vendor=Object.fromEntries(Array.from({length:99},(_,i)=>
      ['vendor_'+i,'literal']));
    const fields={src_ip:'192.0.2.1',...vendor,source_ip:'198.51.100.1'};
    const status=normalizationCandidateScanStatus(suite([fields]));
    expect(status).toMatchObject({eligiblePaths:2,exceeded:false,
      sourceScanTruncated:false});
    const recommendations=suggestNormalizationCandidatesFromSuite(suite([fields]),[]);
    expect(recommendations.map(r=>r.source)).toEqual(['src_ip','source_ip']);
    expect(recommendations.every(r=>r.target==='srcip'&&
      r.confidence==='REVIEW'&&!r.safeForBulk)).toBe(true);
    const reversed=Object.fromEntries(Object.entries(fields).reverse());
    const backwards=suggestNormalizationCandidatesFromSuite(suite([reversed]),[]);
    expect(backwards.map(r=>[r.source,r.confidence,r.safeForBulk]).sort())
      .toEqual(recommendations.map(r=>[r.source,r.confidence,r.safeForBulk]).sort());
  });
  it('fails closed only after the independently bounded 1024-leaf source scan',()=>{
    const safe=Object.fromEntries(Array.from({length:1024},(_,i)=>
      ['node_'+i,{src_ip:'192.0.2.1'}]));
    const eligible=normalizationCandidateScanStatus(suite([safe]));
    expect(eligible).toMatchObject({eligiblePaths:1024,exceeded:false,
      sourceScanTruncated:false});
    const over={...safe,node_1024:{src_ip:'198.51.100.1'}};
    expect(normalizationCandidateScanStatus(suite([over])))
      .toMatchObject({exceeded:true,sourceScanTruncated:true,paths:[]});
    expect(suggestNormalizationCandidatesFromSuite(suite([over]),[])).toEqual([]);
  });

  it('refuses a partial result if the official candidate budget is exceeded',()=>{
    const events:Record<string,unknown>[]=[];
    for(let i=0;i<MAX_OFFICIAL_CANDIDATE_SCAN+1;i+=50){
      const fields:Record<string,unknown>={};
      for(let n=i;n<Math.min(i+50,MAX_OFFICIAL_CANDIDATE_SCAN+1);n++)
        fields['product_'+n]={srcip:'192.0.2.1'};
      events.push(fields);
    }
    const inputs=suite(events);
    const scan=normalizationCandidateScanStatus(inputs);
    expect(scan.exceeded).toBe(true);
    expect(scan.eligiblePaths).toBe(MAX_OFFICIAL_CANDIDATE_SCAN+1);
    expect(suggestNormalizationCandidatesFromSuite(inputs,[])).toEqual([]);
  });
});
