import {describe,it,expect} from 'vitest';
import {suggestNormalizationCandidates} from './normalizationCandidates';
describe('unverified browser-only normalization hints',()=>{
 it('recommends source-backed aliases without claiming official dictionary support',()=>{
  expect(suggestNormalizationCandidates({src_ip:'192.0.2.1',dst_port:443},[])).toEqual([
   expect.objectContaining({source:'src_ip',target:'srcip',confidence:'HIGH',catalogVerified:false}),
   expect.objectContaining({source:'dst_port',target:'dstport',confidence:'HIGH',catalogVerified:false}),
  ]);
 });
 it('abstains on ambiguous or conflicting destinations and flags invalid values',()=>{
  expect(suggestNormalizationCandidates({src_ip:'999.0.0.1',source_ip:'192.0.2.2',risk_score:78},[]))
   .toEqual([expect.objectContaining({source:'src_ip',confidence:'REVIEW'})]);
  expect(suggestNormalizationCandidates({src_ip:'192.0.2.1'},[{id:'1',source:'x',target:'srcip',type:'ip'}])).toEqual([]);
 });
});
