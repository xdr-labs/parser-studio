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
