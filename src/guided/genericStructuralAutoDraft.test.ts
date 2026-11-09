import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';

describe('beginner automatic Generic Structural handoff',()=>{
  it('prepares named BIG-IP fields while requiring review for competing hostname aliases',()=>{
    const raw='Oct 15 00:14:27 bigip-waf01 ASM: unit_hostname="bigip-waf01",management_ip_address="10.1.1.10",request_status="blocked",ip_client="203.0.113.210",protocol="HTTPS",date_time="2026-10-15T00:14:27+09:00",dest_port="443",dest_ip="10.20.1.25",uri="/api/login"';
    const result=buildAutomaticGenericStructuralDraft(raw,createDraft());
    expect(result).not.toBeNull();
    const draft=result!.draft;
    expect(draft.format).toBe('generic_structural');
    expect(draft.mappings.find(x=>x.source==='generic.fields.dest_ip')).toMatchObject({target:'dstip',type:'ip'});
    // HTTPS is an application protocol label. Do not silently assume TCP
    // port 443 is an official L4 destination without transport evidence.
    expect(draft.mappings.find(x=>x.source==='generic.fields.dest_port'))
      .toMatchObject({target:'dest_port'});
    expect(draft.mappings.find(x=>x.source==='generic.fields.ip_client')).toMatchObject({target:'srcip',type:'ip'});
    // BIG-IP HTTPS is an application protocol, not an L4 TCP/UDP/ICMP name.
    // Keep it vendor-local rather than corrupt Stellar 7.0 proto_name.
    expect(draft.mappings.find(x=>x.source==='generic.fields.protocol')).toMatchObject({target:'protocol',type:'string'});
    expect(draft.mappings.find(x=>x.source==='generic.fields.date_time')).toMatchObject({target:'timestamp',type:'timestamp'});
    // Both the Syslog envelope host and the BIG-IP unit_hostname contain
    // valid hostname values; neither is silently selected as authoritative.
    expect(draft.mappings.find(x=>x.source==='syslog.host')).toMatchObject({target:'host'});
    expect(draft.mappings.find(x=>x.source==='generic.fields.unit_hostname')).toBeDefined();
  });

  it('auto-adopts RFC3164-wrapped positional firewall CSV without requiring a repair click',()=>{
    const raw='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy';
    const result=buildAutomaticGenericStructuralDraft(raw,createDraft());
    expect(result).not.toBeNull();
    expect(result!.draft.format).toBe('generic_structural');
    expect(result!.suite.counts.failures).toBe(0);
    expect(result!.suite.events[0]!.fields).toMatchObject({
      syslog:{pri:'14',hostname:'PA-FW01'},
      generic:{mode:'panos_traffic_csv',fields:{type:'TRAFFIC',src:'10.10.20.15',dport:'443',action:'allow'}},
    });
    expect(result!.draft.mappings.find(x=>x.source==='generic.fields.src')).toMatchObject({target:'srcip',type:'ip'});
    expect(result!.draft.mappings.find(x=>x.source==='generic.fields.dst')).toMatchObject({target:'dstip',type:'ip'});
    expect(result!.draft.mappings.find(x=>x.source==='generic.fields.sport')).toMatchObject({target:'srcport'});
    expect(result!.draft.mappings.find(x=>x.source==='generic.fields.dport')).toMatchObject({target:'dstport'});
    expect(result!.draft.mappings.find(x=>x.source==='generic.fields.protocol')).toMatchObject({target:'proto_name'});
    expect(result!.draft.mappings.find(x=>x.source==='generic.fields.action')).toMatchObject({target:'action'});
    expect(result!.draft.mappings.length).toBeLessThanOrEqual(60);
  });

  it('auto-adopts common year-bearing ASA wrappers as a fully parsed known structure',()=>{
    const raw='<166>Oct 15 2026 00:05:03 ASA-EDGE01 : %ASA-6-302013: Built outbound TCP connection 18745213 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)';
    const result=buildAutomaticGenericStructuralDraft(raw,createDraft());
    expect(result).not.toBeNull();
    expect(result!.draft.mappings.find(x=>x.source==='asa.src_ip')).toMatchObject({target:'srcip',type:'ip'});
    expect(result!.draft.mappings.find(x=>x.source==='asa.dst_ip')).toMatchObject({target:'dstip',type:'ip'});
    expect(result!.draft.mappings.find(x=>x.source==='asa.protocol')).toMatchObject({target:'proto_name'});
  });

  it('does not auto-adopt Generic Structural when a declared relay profile is present',()=>{
    // Nested PRI: the relay header is followed by the original <190> device PRI.
    // The backend adapter does not accept declared relays on generic_structural,
    // so adopting it would turn "structurally parsed" into a locked Map Fields step.
    const raw='<14>Oct 29 10:00:00 relay-a fortigate: <190>date=2024-08-28 time=10:33:52 devname="MYFWNAME" devid="FG3000000" logid="1700062307" type="utm" subtype="ssl" level="information" srcip=10.2.3.4 srcport=59968 dstip=10.3.2.1 dstport=8443';
    expect(buildAutomaticGenericStructuralDraft(raw,createDraft())).not.toBeNull();
    const withRelay={...createDraft(),forwarder:{maxHops:1 as const,relayHosts:['relay-a']}};
    expect(buildAutomaticGenericStructuralDraft(raw,withRelay)).toBeNull();
  });
});
