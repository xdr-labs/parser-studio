/**
 * `sport` beside client-side endpoint names is not approved as the official source port (independent audit of
 * e8d8d26, finding A-2; reproduced on Ruby 2.4.9 with `cip sip cport sport`: srcport held the server port 443).
 *
 * `sport` abbreviates "source port" beside `dport`. Records that name their endpoints client and server
 * (`cip sip cport sport`, as W3C does with c-ip, s-ip and s-port) use it for the SERVER port. The name alone does
 * not say which one it is. A list of client-side names cannot be complete (final audit F-1: client_ip_address,
 * client_hostname, client/server, remote/local still gave srcport), so the rule is the pair: `sport` is approved as
 * the source port only when the same record has a destination port; otherwise it is offered for review and never
 * applied automatically. SYNTHETIC values.
 */
import {describe,expect,it} from 'vitest';
import {suggestNormalizationCandidates,suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import type {SuiteResult} from '../model';

const sportOf=(fields:Record<string,unknown>)=>suggestNormalizationCandidates(fields,[]).find(item=>item.source.endsWith('sport'));

describe('sport is the source port only beside a destination port',()=>{
  it('is approved beside dport, dst_port or dstport',()=>{
    expect(sportOf({sip:'10.3.3.5',dip:'192.0.2.30',sport:52000,dport:443})).toMatchObject({target:'srcport',confidence:'HIGH'});
    expect(sportOf({client_ip:'10.2.2.5',sport:52000,dport:443})).toMatchObject({target:'srcport',confidence:'HIGH'});
    expect(sportOf({cip:'10.2.2.5',sport:52000,dst_port:443})).toMatchObject({target:'srcport',confidence:'HIGH'});
    expect(sportOf({sport:52000,dstport:443})).toMatchObject({target:'srcport',confidence:'HIGH'});
  });
  it.each([
    {cip:'10.2.2.5',sip:'192.0.2.20',cport:51000,sport:443},
    {'c-ip':'10.2.2.5',sport:443},
    {client_ip_address:'10.2.2.1',server_ip_address:'192.0.2.20',sport:443},
    {client_hostname:'pc-1',server_hostname:'web-1',sport:443},
    {client:'10.2.2.1',server:'192.0.2.20',sport:443},
    {remote_ip:'10.2.2.1',local_ip:'192.0.2.20',sport:443},
    {category:'web',count:3,sport:52000},
  ])('is not approved without a destination port: %j',fields=>{
    expect(sportOf(fields)).toMatchObject({target:'srcport',confidence:'REVIEW'});
  });
  it('looks at the names beside it, not at names of another object',()=>{
    expect(sportOf({body:{sport:52000,dport:443}})).toMatchObject({source:'body.sport',confidence:'HIGH'});
    expect(sportOf({meta:{dport:443},body:{sport:52000}})).toMatchObject({source:'body.sport',confidence:'REVIEW'});
  });
  it('is not approved when one event of the sample has no destination port beside it',()=>{
    const suite={events:[{fields:{sport:52000,dport:443}},{fields:{sport:443}}]} as unknown as SuiteResult;
    expect(suggestNormalizationCandidatesFromSuite(suite,[]).find(item=>item.source==='sport')).toMatchObject({confidence:'REVIEW'});
  });
  it('leaves the other source-port names alone',()=>{
    const named=(fields:Record<string,unknown>,source:string)=>suggestNormalizationCandidates(fields,[]).find(item=>item.source===source);
    expect(named({cip:'10.2.2.5',src_port:52000},'src_port')).toMatchObject({target:'srcport',confidence:'HIGH'});
    expect(named({source_port:52000},'source_port')).toMatchObject({target:'srcport',confidence:'HIGH'});
  });
});
