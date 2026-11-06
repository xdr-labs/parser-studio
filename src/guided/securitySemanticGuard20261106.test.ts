import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

const candidates=(...fields:Record<string,unknown>[])=>suggestNormalizationCandidatesFromSuite(
  {events:fields.map(value=>({fields:value}))} as unknown as SuiteResult,[],
);
const official=(...fields:Record<string,unknown>[])=>candidates(...fields)
  .filter(candidate=>candidate.confidence==='HIGH'&&candidate.safeForBulk)
  .map(candidate=>[candidate.source,candidate.target]);

describe('cross-vendor Stellar 7.0 semantic false-friend oracle, 2026-11-06',()=>{
  it('preserves Fortinet traffic session-close as vendor action without losing valid L4 fields',()=>{
    const fields={logid:'0000000013',type:'traffic',vd:'vdom1',proto:'6',
      srcip:'10.1.100.11',srcport:'58012',dstip:'23.59.154.35',dstport:'80',
      action:'close',utmaction:'allow',policyid:1,duration:116};
    const mapped=official(fields);
    expect(mapped).not.toContainEqual(['action','action']);
    for(const pair of [['srcip','srcip'],['dstip','dstip'],['srcport','srcport'],
      ['dstport','dstport'],['proto','proto'],['policyid','fw_policy_id']]){
      expect(mapped).toContainEqual(pair);
    }
  });
  it('keeps admin-login and VPN-negotiation actions vendor scoped, but accepts blocking actions',()=>{
    for(const action of ['login','negotiate','close','Detection','user.session.start']){
      expect(official({action,srcip:'192.0.2.1'})).not.toContainEqual(['action','action']);
    }
    for(const action of ['allow','allowed','block','blocked','deny','denied','drop','dropped',
      'accept','permitted','reject','quarantine']){
      expect(official({action})).toContainEqual(['action','action']);
    }
  });
  it('does not relabel AWS identity type or WatchGuard ICMP type as a Windows-agent field',()=>{
    expect(official({userIdentity:{type:'IAMUser',userName:'John'},
      eventTime:'2014-07-16T15:49:27Z',sourceIPAddress:'192.0.2.110'}))
      .not.toContainEqual(['userIdentity.type','type']);
    expect(official({parserstudio_source:{generic:{kv:{type:'8',duration:'0'}}}}))
      .not.toContainEqual(['parserstudio_source.generic.kv.type','type']);
    expect(official({type:'event',subtype:'system',action:'login'}))
      .not.toContainEqual(['type','type']);
  });
  it('does not call Suricata or Okta event families Stellar ML event_type',()=>{
    expect(official({event_type:'alert',src_ip:'192.0.2.10'}))
      .not.toContainEqual(['event_type','event_type']);
    expect(official({eventType:'user.session.start',client:{ipAddress:'192.0.2.44'}}))
      .not.toContainEqual(['eventType','event_type']);
  });
  it('does not silently treat vendor duration as milliseconds, but supports explicit ms units',()=>{
    expect(official({parserstudio_source:{generic:{kv:{duration:'14'}}}}))
      .not.toContainEqual(['parserstudio_source.generic.kv.duration','duration']);
    expect(official({duration:116})).not.toContainEqual(['duration','duration']);
    expect(official({duration_ms:14000})).toContainEqual(['duration_ms','duration']);
  });
  it('does not relabel Suricata IDS signature severity into Stellar security severity',()=>{
    const src={event_type:'alert',src_ip:'192.0.2.10',
      alert:{action:'allowed',signature_id:2018358,severity:2}};
    expect(official(src)).not.toContainEqual(['alert.severity','severity']);
    expect(official(src)).toContainEqual(['src_ip','srcip']);
    expect(official(src)).toContainEqual(['alert.action','action']);
  });
});
