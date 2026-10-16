import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const samples=[
  {id:'cisco-ios-sequence',raw:'<189>12345: Oct 16 15:44:21.123 KST: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 192.0.2.10] [localport: 22]'},
  {id:'cisco-ios-classic',raw:'<189>Oct 16 15:44:21 router01 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 192.0.2.10] [localport: 22]'},
  {id:'cisco-ios-config',raw:'<189>321: Oct 16 15:44:22.100 UTC: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.0.2.10)'},
  {id:'nginx-combined-v4',raw:'192.0.2.10 - alice [16/Oct/2026:15:44:21 +0900] "GET /login?next=%2Fadmin HTTP/1.1" 403 123 "https://example.test/" "Mozilla/5.0 Test Agent"'},
  {id:'nginx-combined-v6',raw:'2001:db8::10 - - [16/Oct/2026:15:44:22 +0000] "POST /api/login HTTP/2.0" 401 78 "-" "curl/8.0"'},
  {id:'apache-common',raw:'198.51.100.20 - - [16/Oct/2026:15:44:23 +0000] "GET /health HTTP/1.1" 200 12'},
  {id:'squid-native',raw:'1792152264.123 321 192.0.2.10 TCP_DENIED/403 1234 GET https://example.test/login - HIER_NONE/- text/html'},
  {id:'squid-ipv6',raw:'1792152265.456 12 2001:db8::10 TCP_TUNNEL/200 0 CONNECT example.test:443 alice HIER_DIRECT/198.51.100.20 -'},
  {id:'bind-query',raw:'<30>Oct 16 15:44:21 dns01 named[1234]: client @0x7f1a 192.0.2.10#51514 (example.test): query: example.test IN A +E(0)K (192.0.2.53)'},
  {id:'bind-query-v6',raw:'<30>2026-10-16T15:44:21Z dns01 named[1234]: client @0x7f1a 2001:db8::10#51514 (example.test): query: example.test IN AAAA +E(0)K (2001:db8::53)'},
  {id:'linux-audit-syscall',raw:'type=SYSCALL msg=audit(1792152261.123:420): arch=c000003e syscall=59 success=yes exit=0 a0=55 exe="/usr/bin/sudo" key="privilege"'},
  {id:'linux-audit-avc',raw:'type=AVC msg=audit(1792152261.456:421): avc: denied { read } for pid=123 comm="httpd" name="shadow" dev="dm-0" ino=42 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file'},
  {id:'esxi-rfc5424-sd',raw:'<166>1 2026-10-16T15:44:21Z esxi01 hostd 12345 VIM [Originator@6876 sub="Vimsvc.ha-eventmgr" opID="abc-123"] Event 42: User admin logged in'},
  {id:'esxi-legacy',raw:'<166>Oct 16 15:44:21 esxi01 hostd[12345]: [Originator@6876 sub=Vimsvc.ha-eventmgr opID=abc-123] Event 42: User admin logged in'},
  {id:'suricata-fast',raw:'<134>Oct 16 15:44:21 IDS01 suricata: [1:2024001:1] ET WEB_SERVER Possible attack [Classification: Web Application Attack] [Priority: 1] {TCP} 192.0.2.10:51514 -> 198.51.100.20:443'},
] as const;

describe('round 6 residual security-log corpus',()=>{
  it('measures formats still outside deterministic structural coverage',()=>{
    const rows=samples.map(sample=>{
      const result=extractGenericStructural(sample.raw);
      return {id:sample.id,parsed:result.errors.length===0,keys:Object.keys(result.fields)};
    });
    const summary={
      total:rows.length,parsed:rows.filter(row=>row.parsed).length,
      failures:rows.filter(row=>!row.parsed).map(row=>row.id),
      successes:rows.filter(row=>row.parsed).map(row=>({id:row.id,keys:row.keys})),
    };
    console.log('ROUND6_RESIDUAL '+JSON.stringify(summary));
    expect(rows).toHaveLength(samples.length);
  });
});
