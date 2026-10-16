import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

const bodies=[
  {
    id:'cisco-asa',
    text:'%ASA-6-302013: Built outbound TCP connection 18745213 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)',
  },
  {
    id:'juniper-rt-flow',
    text:'RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.83.99/40275->192.168.32.1/161 None 192.168.83.99/40275->192.168.32.1/161 None None 17 allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255',
  },
  {
    id:'checkpoint-bracket-kv',
    text:'CheckPoint[8363]: [action:"Accept"; src:"192.0.2.1"; product:"VPN-1 & FireWall-1"; group:"ops"; note:"x;y"]',
  },
  {
    id:'cisco-ise-comma-kv',
    text:'APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: failed, AD-Admin=ise.host.local, AD-Domain=host.local, AD-IP-Address=192.0.2.10',
  },
  {
    id:'watchguard',
    text:'FVE6035FD3AE3 (2024-01-19T08:48:15) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.1.2 175.16.199.1 39398 25 msg="SMTP request" proxy_act="SMTP-Outgoing.1" rcvd_bytes="272" sent_bytes="282"',
  },
  {
    id:'sophos-kv',
    text:'ulogd[12511]: id="2021" severity="info" sys="SecureNet" sub="packetfilter" name="Packet dropped" action="drop"',
  },
] as const;

const wrappers=[
  (body:string)=>'<134>Oct 16 15:44:21 SEC01 '+body,
  (body:string)=>'<134>Oct 16 2026 15:44:21 SEC01 '+body,
  (body:string)=>'<134>Oct 16 15:44:21 2026 SEC01 '+body,
  (body:string)=>'<134>2026-10-16T15:44:21Z SEC01 '+body,
  (body:string)=>'<134>2026-10-16 15:44:21.123 +0900 SEC01 '+body,
] as const;

describe('vendor body cross-wrapper residual PoC',()=>{
  it('measures which body parsers remain coupled to their legacy header shape',()=>{
    const rows=[] as Array<{id:string;wrapper:number;envelope:boolean;structured:boolean}>;
    for(const body of bodies){
      wrappers.forEach((wrap,index)=>{
        const raw=wrap(body.text);
        rows.push({
          id:body.id,
          wrapper:index,
          envelope:parseSyslogEnvelope(raw)!==null,
          structured:extractGenericStructural(raw).errors.length===0,
        });
      });
    }
    const summary={
      total:rows.length,
      envelope:rows.filter(row=>row.envelope).length,
      structured:rows.filter(row=>row.structured).length,
      byBody:Object.fromEntries(bodies.map(body=>[
        body.id,
        {
          structured:rows.filter(row=>row.id===body.id&&row.structured).length,
          failures:rows.filter(row=>row.id===body.id&&!row.structured).map(row=>row.wrapper),
        },
      ])),
    };
    console.log('VENDOR_WRAPPER_RESIDUAL '+JSON.stringify(summary));
    expect(summary.envelope).toBe(rows.length);
    expect(summary.structured).toBe(rows.length);
    for(const body of bodies){
      expect(summary.byBody[body.id]?.structured,body.id).toBe(wrappers.length);
      expect(summary.byBody[body.id]?.failures,body.id).toEqual([]);
    }
  });

  it('fails closed for malformed known vendor bodies behind valid envelopes',()=>{
    const malformed=[
      '%ASA-9-302013: Built outbound TCP connection 1 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)',
      '%ASA-6-302013: Built outbound TCP connection 1 for outside:203.0.113.50/70000 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)',
      'RT_FLOW: RT_FLOW_SESSION_CREATE: session created without any network tuple',
      'RT_FLOW: UNKNOWN_EVENT: 192.0.2.1/1->198.51.100.2/2',
      'CheckPoint[8363]: [constructor:"bad"; action:"Accept"]',
      'CheckPoint[8363]: [action:"Accept"; src:"unterminated]',
      'FVE6035FD3AE3 (2024-13-19T08:48:15) firewall: msg_id="1BFF-000F" Allow trust untrust tcp 10.0.1.2 175.16.199.1 39398 25',
      'FVE6035FD3AE3 (2024-01-19T08:48:15) firewall: msg_id="BAD" Allow trust untrust tcp 10.0.1.2 175.16.199.1 39398 25',
      'FVE6035FD3AE3 (2024-01-19T08:48:15) firewall: msg_id="1BFF-000F" Allow trust untrust tcp one-ip 175.16.199.1 39398 25',
    ];
    const accepted=malformed.filter(body=>
      extractGenericStructural('<134>2026-10-16T15:44:21Z SEC01 '+body).errors.length===0
    );
    console.log('VENDOR_WRAPPER_MALFORMED '+JSON.stringify({total:malformed.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
