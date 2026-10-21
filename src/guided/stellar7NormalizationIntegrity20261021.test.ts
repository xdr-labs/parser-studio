import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidates,suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

const sample=(...fields:Record<string,unknown>[])=>({
  events:fields.map(value=>({fields:value})),
} as unknown as SuiteResult);

describe('Stellar Cyber 7.0 normalization integrity (catalog-backed, not target verified)',()=>{
  it('must not recommend malformed IPv6 as an automatic official IP mapping',()=>{
    expect(suggestNormalizationCandidates({src_ip:':::'},[])).toEqual([
      expect.objectContaining({target:'srcip',confidence:'REVIEW',safeForBulk:false}),
    ]);
  });

  it('does not infer a security action from a vendor-specific request status',()=>{
    expect(suggestNormalizationCandidates({request_status:200},[])).toEqual([]);
    expect(suggestNormalizationCandidates({request_status:'blocked'},[])).toEqual([]);
    expect(suggestNormalizationCandidates({body:{request_status:200}},[])).toEqual([]);
  });

  it('keeps every conflicting source alias review-only, regardless of enumeration order',()=>{
    for(const fields of [
      {src_ip:'192.0.2.10',source_ip:'203.0.113.20'},
      {source_ip:'203.0.113.20',src_ip:'192.0.2.10'},
    ]){
      const candidates=suggestNormalizationCandidates(fields,[]);
      expect(candidates.map(candidate=>candidate.source).sort()).toEqual(['source_ip','src_ip']);
      expect(candidates.every(candidate=>candidate.target==='srcip'&&
        candidate.confidence==='REVIEW'&&!candidate.safeForBulk)).toBe(true);
      expect(candidates.every(candidate=>candidate.explanation.includes('multiple'))).toBe(true);
      expect(suggestNormalizationCandidatesFromSuite(sample(fields),[],{},
        {skipAmbiguousTargets:true})).toEqual([]);
    }
  });

  it('makes sparse cross-event evidence review-only instead of counting one valid IP as complete',()=>{
    const candidates=suggestNormalizationCandidatesFromSuite(sample(
      {src_ip:'192.0.2.10'},{action:'deny'},{action:'allow'}
    ),[]);
    expect(candidates.find(candidate=>candidate.target==='srcip')).toMatchObject({
      observed:1,total:3,confidence:'REVIEW',safeForBulk:false,
    });
    expect(candidates.find(candidate=>candidate.target==='action')).toMatchObject({
      observed:2,total:3,confidence:'REVIEW',safeForBulk:false,
    });
  });

  it('requires at least one informative value before offering a HIGH mapping',()=>{
    expect(suggestNormalizationCandidatesFromSuite(sample(
      {src_ip:'N/A'},{src_ip:''}
    ),[])).toEqual([
      expect.objectContaining({target:'srcip',confidence:'REVIEW',safeForBulk:false}),
    ]);
  });

  it('preserves safe high-confidence single-source 7.0 mappings',()=>{
    expect(suggestNormalizationCandidatesFromSuite(sample(
      {src_ip:'2001:db8::10',action:'deny'},
      {src_ip:'192.0.2.1',action:'allow'}
    ),[])).toEqual(expect.arrayContaining([
      expect.objectContaining({source:'src_ip',target:'srcip',confidence:'HIGH',safeForBulk:true,catalogRelease:'7.0.xs'}),
      expect.objectContaining({source:'action',target:'action',confidence:'HIGH',safeForBulk:true,catalogRelease:'7.0.xs'}),
    ]));
  });
});
