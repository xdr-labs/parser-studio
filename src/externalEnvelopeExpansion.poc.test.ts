import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseCiscoFirewallEnvelope} from './ciscoFirewallEnvelope';
import {parseBindQueryLog} from './bindQueryLog';

describe('external-holdout envelope expansion PoC',()=>{
  it('preserves previously unknown ASA/FTD message IDs through one common message envelope',()=>{
    const samples=[
      'ASA-2-106001: Inbound TCP connection denied from 192.168.2.2/43803 to 10.10.10.10/14322 flags SYN on interface out111',
      'ASA-2-106006: Deny inbound UDP from 192.168.2.2/65020 to 10.10.10.10/65021 on interface fw111',
      'ASA-4-106021: Deny TCP reverse path check from 192.168.2.2 to 10.10.10.10 on interface fw111',
      '%FTD-5-111008: User admin executed the show running-config command',
    ];
    for(const raw of samples){
      const envelope=parseCiscoFirewallEnvelope(raw);
      expect(envelope,raw).not.toBeNull();
      const parsed=extractGenericStructural(raw);
      expect(parsed.errors,raw).toEqual([]);
      expect(parsed.fields.cisco_firewall,raw).toMatchObject({message_id:expect.stringMatching(/^\d{6}$/)});
    }
  });

  it('does not let the generic Cisco envelope rescue message IDs owned by strict network grammars',()=>{
    const invalid=[
      'ASA-6-302013: Built outbound TCP connection 1 for outside:203.0.113.1/70000 (203.0.113.1/443) to inside:10.0.0.1/443 (198.51.100.1/443)',
      'ASA-4-106023: Deny tcp src outside:999.0.0.1/5000 dst inside:192.0.2.2/443 by access-group "outside" [0x0, 0x0]',
    ];
    expect(invalid.filter(raw=>parseCiscoFirewallEnvelope(raw)!==null)).toEqual([]);
    expect(invalid.filter(raw=>extractGenericStructural(raw).errors.length===0)).toEqual([]);
  });

  it('reuses one full BIND timestamp envelope around the existing query-body grammar',()=>{
    const samples=[
      '17-Feb-2018 23:06:56.326 queries: info: client 172.26.0.1#12345 (test.example.com): query: test.example.com IN A +E(0)K (172.26.0.3)',
      '30-Jun-2018 15:50:00.999 queries: info: client @0x7f64500020ef 192.168.10.48#60061 (example.test): query: example.test IN PTR + (192.168.2.2)',
    ];
    for(const raw of samples){
      const parsed=parseBindQueryLog(raw);
      expect(parsed,raw).not.toBeNull();
      expect(extractGenericStructural(raw).errors,raw).toEqual([]);
    }
  });

  it('rejects impossible BIND dates, invalid endpoints, mismatched query identity, and malformed Cisco headers',()=>{
    const invalidBind=[
      '30-Feb-2018 23:06:56.326 queries: info: client 172.26.0.1#12345 (test.example.com): query: test.example.com IN A + (172.26.0.3)',
      '17-Feb-2018 25:06:56.326 queries: info: client 172.26.0.1#12345 (test.example.com): query: test.example.com IN A + (172.26.0.3)',
      '17-Feb-2018 23:06:56.326 queries: info: client 999.0.0.1#12345 (test.example.com): query: test.example.com IN A + (172.26.0.3)',
      '17-Feb-2018 23:06:56.326 queries: info: client 172.26.0.1#12345 (other.example.com): query: test.example.com IN A + (172.26.0.3)',
    ];
    expect(invalidBind.filter(raw=>parseBindQueryLog(raw)!==null)).toEqual([]);
    const invalidCisco=[
      'ASA-9-106001: invalid severity',
      'ASA-2-12345: invalid message id',
      'ASA-2-106001:',
      'ASA-2-106001: nested ASA-2-106002: payload',
    ];
    expect(invalidCisco.filter(raw=>parseCiscoFirewallEnvelope(raw)!==null)).toEqual([]);
  });
});
