import {describe,expect,it} from 'vitest';
import {createDraft} from './model';
import {preview} from './parser';
import {extractGenericStructural} from './genericStructural';
import {buildAutomaticGenericStructuralDraft} from './guided/genericStructuralAutoDraft';

// Golden r2_watchguard_traffic: the three "Read a Log Message" examples of the Fireware Help (PUBLISHER_ORIGINAL).
const WG=[
  '2024-03-29 15:00:50 Member2 Allow 192.168.228.202 10.0.1.1 webcache/tcp 42973 8080 3-Trusted 1-WCI Allowed 60 63 (Outgoing-proxy-00) proc_id="firewall" rc="100" src_ip_nat="69.164.168.163" tcp_info="offset 10 S 2982213793 win 2105" msg_id="3000-0148"',
  '2024-03-29 18:00:54 Allow 10.0.1.2 100.100.100.11 http/tcp 42017 80 Trusted External Allowed (HTTP-proxy.1-00) proc_id="firewall" rc="406" msg_id="3000-0176" src_ip_nat="100.100.100.10" flags="SDdF" duration="14" sent_pkts="10" rcvd_pkts="5" sent_bytes="564" rcvd_bytes="785"',
  '2024-04-01 23:39:46 Deny 10.0.1.131 10.0.1.1 echo-request/icmp Trusted Firebox Denied 84 64 (Ping-00) proc_id="firewall" rc="101" msg_id="3000-0148" type="8" duration="0" sent_pkts="1" rcvd_pkts="0" sent_bytes="84" rcvd_bytes="0"',
];
// Golden meraki_mx_flows_ids: Meraki syslog samples (PUBLISHER_ORIGINAL; nbsp -> space, MAC masked by the publisher).
const MERAKI=[
  '948136486.721741837 MX60 flows src=192.168.10.254 dst=8.8.8.8 mac=00:18:0A:XX:XX:XX protocol=udp sport=9562 dport=53 pattern: allow all',
  '1490031971.951780201 ANB_MX80 security_event ids_alerted signature=1:39867:3 priority=3 timestamp=1490031971.693691 shost=00:15:5D:1E:08:04 direction=egress protocol=udp/ip src=192.168.30.10:49243 dst=71.10.216.1:53 message: INDICATOR-COMPROMISE Suspicious .tk dns query',
];
const tuple=(out:Record<string,unknown>)=>[out.srcip,out.dstip,out.srcport,out.dstport];

describe('WatchGuard Traffic Monitor layout',()=>{
  it('names the documented positions, with or without cluster member, ports, packet length and TTL',()=>{
    const [member,standalone,icmp]=WG.map(line=>extractGenericStructural(line,undefined,'dedicated'));
    expect(member!.errors).toEqual([]);
    expect(member!.fields).toMatchObject({watchguard_header:{date:'2024-03-29',time:'15:00:50',cluster:'Member2'},
      watchguard:{disp:'Allow',src_ip:'192.168.228.202',dst_ip:'10.0.1.1',service:'webcache',protocol:'tcp',
        src_port:'42973',dst_port:'8080',src_intf:'3-Trusted',dst_intf:'1-WCI',connection_action:'Allowed',
        pckt_len:'60',ttl:'63',policy:'Outgoing-proxy-00',kv:{msg_id:'3000-0148',tcp_info:'offset 10 S 2982213793 win 2105'}},
      generic:{mode:'watchguard_traffic_monitor'}});
    expect(standalone!.fields).toMatchObject({watchguard:{disp:'Allow',src_ip:'10.0.1.2',src_port:'42017',dst_port:'80'}});
    expect((standalone!.fields.watchguard_header as Record<string,unknown>).cluster).toBeUndefined();
    expect((standalone!.fields.watchguard as Record<string,unknown>).pckt_len).toBeUndefined();
    expect(icmp!.fields).toMatchObject({watchguard:{protocol:'icmp',src_intf:'Trusted',dst_intf:'Firebox',pckt_len:'84',ttl:'64'}});
    expect((icmp!.fields.watchguard as Record<string,unknown>).src_port).toBeUndefined();
  });

  it('maps the endpoints and ports, and never a word after the time as the host name',()=>{
    const source=WG.join('\n');
    const built=buildAutomaticGenericStructuralDraft(source,createDraft())!;
    const events=preview(source,built.draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL','FULL']);
    expect(events.map(event=>tuple(event.normalized))).toEqual([
      ['192.168.228.202','10.0.1.1',42973,8080],['10.0.1.2','100.100.100.11',42017,80],['10.0.1.131','10.0.1.1',undefined,undefined]]);
    expect(events.map(event=>event.normalized.proto_name)).toEqual(['tcp','tcp','icmp']);
    expect(events.map(event=>event.normalized.hostname)).toEqual([undefined,undefined,undefined]);
  });

  it('declines what the layout does not hold',()=>{
    for(const line of [
      WG[1]!.replace(' 42017 80 ',' 42017 80000 '),                 // not a port
      WG[1]!.replace(' msg_id="3000-0176"',''),                      // no message ID
      WG[1]!.replace(' Allow ',' Permit '),                          // not a documented disposition
      WG[1]!.replace(' 10.0.1.2 ',' 10.0.1.256 '),                   // not an address
      WG[1]!.replace('(HTTP-proxy.1-00)','HTTP-proxy.1-00'),         // no policy
    ]){
      const read=extractGenericStructural(line,undefined,'dedicated');
      expect((read.fields.generic as Record<string,unknown>|undefined)?.mode,line).not.toBe('watchguard_traffic_monitor');
    }
  });
});

describe('Meraki syslog layout',()=>{
  it('ends the pairs at the documented label: the rule is no part of the value of dport',()=>{
    const flows=extractGenericStructural(MERAKI[0]!,undefined,'dedicated');
    expect(flows.fields).toMatchObject({meraki_header:{epoch:'948136486.721741837',device:'MX60',record_type:'flows'},
      generic:{mode:'meraki_flows',kv:{src:'192.168.10.254',dst:'8.8.8.8',protocol:'udp',sport:'9562',dport:'53'},pattern:'allow all'}});
    const ids=extractGenericStructural(MERAKI[1]!,undefined,'dedicated');
    expect(ids.fields).toMatchObject({meraki_header:{record_type:'security_event',event_type:'ids_alerted'},
      generic:{mode:'meraki_security_event',kv:{src:'192.168.30.10:49243',dst:'71.10.216.1:53',protocol:'udp/ip'},
        message:'INDICATOR-COMPROMISE Suspicious .tk dns query'}});
  });

  it('maps the flows record on its own; the address:port of the IDS record is not an address',()=>{
    const source=MERAKI.join('\n');
    const built=buildAutomaticGenericStructuralDraft(source,createDraft())!;
    expect(built.draft.eventProfiles?.discriminator).toBe('generic.mode');
    const [flows,ids]=preview(source,built.draft).events.map(event=>event.normalized);
    expect(tuple(flows!)).toEqual(['192.168.10.254','8.8.8.8',9562,53]);
    expect(tuple(ids!)).toEqual([undefined,undefined,undefined,undefined]);
    expect(JSON.stringify(ids)).toContain('"src":"192.168.30.10:49243"');
    expect(JSON.stringify(flows)).toContain('"pattern":"allow all"');
    // The header epoch and the timestamp= pair of the IDS record are two fields with their own names.
    const idsText=JSON.stringify(ids);
    expect(idsText).toContain('"epoch":"1490031971.951780201"');
    expect(idsText).toContain('"timestamp":"1490031971.693691"');
    expect(idsText).not.toContain('"timestamp":"1490031971.951780201"');
  });

  it('declines a line that is not the layout',()=>{
    for(const line of [
      MERAKI[0]!.replace('flows','flowz'),
      MERAKI[0]!.replace(' dst=8.8.8.8',''),
      MERAKI[0]!.replace('sport=9562 ','sport=9562  '),
      MERAKI[0]!.replace('dport=53','dport=53 dport=54'),
    ]){
      const read=extractGenericStructural(line,undefined,'dedicated');
      expect(String((read.fields.generic as Record<string,unknown>|undefined)?.mode),line).not.toMatch(/^meraki_/u);
    }
  });
});
