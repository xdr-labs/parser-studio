import {describe,it,expect} from 'vitest';
import {sourceHasExcludedPortSegment,explicitPortSourceAlias} from './sourcePortPolicy';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import type {SuiteResult} from '../model';

const denied=['nat.source-port','nat_source.source-port','post_nat.source-port',
  'translated_source.source-port','source_nat.source-port','postNat.source-port',
  'sourceTranslation.source-port','snat.source-port','dnat.source-port',
  'pre-nat.destination-port','network_address_translation.destination-port'];
const approved=['syslog_sd.element_1.params.source-port','source-port',
  'national.source-port','natural.destination-port'];

describe('shared semantic source identity',()=>{
  it.each(denied)('never promotes translated/NAT %s as the original tuple',source=>{
    const target=source.endsWith('source-port')?'srcport':'dstport';
    expect(sourceHasExcludedPortSegment(source)).toBe(true);
    expect(explicitPortSourceAlias(source,target)).toBe(false);
    const suite={events:[{fields:{[source]:'594'}}]} as unknown as SuiteResult;
    expect(suggestNormalizationCandidatesFromSuite(suite,[],{}).some(c=>
      c.source===source&&c.safeForBulk)).toBe(false);
  });
  it.each(approved)('keeps original field %s eligible',source=>{
    const target=source.endsWith('source-port')?'srcport':'dstport';
    expect(sourceHasExcludedPortSegment(source)).toBe(false);
    expect(explicitPortSourceAlias(source,target)).toBe(true);
  });
});
