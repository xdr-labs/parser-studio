/**
 * `sport` beside client-side endpoint names is not approved as the official source port (independent audit of
 * e8d8d26, finding A-2; reproduced on Ruby 2.4.9 with `cip sip cport sport`: srcport held the server port 443).
 *
 * `sport` abbreviates "source port" beside `dport`. Records that name their endpoints client and server
 * (`cip sip cport sport`, as W3C does with c-ip, s-ip and s-port) use it for the SERVER port. The name alone does
 * not say which one it is, so beside a client-side name and without a destination port in the same record the
 * mapping is offered for review and never applied automatically. SYNTHETIC values.
 */
import {describe,expect,it} from 'vitest';
import {suggestNormalizationCandidates,suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import type {SuiteResult} from '../model';

const sportOf=(fields:Record<string,unknown>)=>suggestNormalizationCandidates(fields,[]).find(item=>item.source.endsWith('sport'));

describe('sport beside client-side endpoint names',()=>{
  it('is the source port beside dport: approved',()=>{
    expect(sportOf({sip:'10.3.3.5',dip:'192.0.2.30',sport:52000,dport:443})).toMatchObject({target:'srcport',confidence:'HIGH'});
  });
  it('is not approved beside a client port',()=>{
    expect(sportOf({cip:'10.2.2.5',sip:'192.0.2.20',cport:51000,sport:443})).toMatchObject({target:'srcport',confidence:'REVIEW'});
  });
  it.each(['c-ip','client_ip','cliaddr','ClientHost'])('is not approved beside the client-side name %s',name=>{
    expect(sportOf({[name]:'10.2.2.5',sport:443})).toMatchObject({target:'srcport',confidence:'REVIEW'});
  });
  it('is approved beside a client-side name when the record also has a destination port',()=>{
    expect(sportOf({client_ip:'10.2.2.5',sport:52000,dport:443})).toMatchObject({target:'srcport',confidence:'HIGH'});
    expect(sportOf({cip:'10.2.2.5',sport:52000,dst_port:443})).toMatchObject({target:'srcport',confidence:'HIGH'});
  });
  it('looks at the names beside it, not at names of another object',()=>{
    expect(sportOf({body:{cport:51000,sport:443}})).toMatchObject({source:'body.sport',confidence:'REVIEW'});
    expect(sportOf({meta:{cport:51000},body:{sport:52000}})).toMatchObject({source:'body.sport',confidence:'HIGH'});
  });
  it('is not approved when one event of the sample has the client-side name beside it',()=>{
    const suite={events:[{fields:{sport:52000}},{fields:{cport:51000,sport:443}}]} as unknown as SuiteResult;
    expect(suggestNormalizationCandidatesFromSuite(suite,[]).find(item=>item.source==='sport')).toMatchObject({confidence:'REVIEW'});
  });
  it('leaves other names alone: an unrelated word starting with c does not count',()=>{
    expect(sportOf({category:'web',count:3,sport:52000})).toMatchObject({target:'srcport',confidence:'HIGH'});
  });
});
