import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

// Independent holdout samples adapted from logstash-patterns-core public specs.
// Source commit: 74a4098582d3331a2b9b18c04d2446f2c0efb648.
// These samples were not used to design the earlier Syslog/PAN fixed corpus.
const samples=[
  {id:'asa-106001',family:'cisco-asa',raw:'ASA-2-106001: Inbound TCP connection denied from 192.168.2.2/43803 to 10.10.10.10/14322 flags SYN on interface out111'},
  {id:'asa-106006',family:'cisco-asa',raw:'ASA-2-106006: Deny inbound UDP from 192.168.2.2/65020 to 10.10.10.10/65021 on interface fw111'},
  {id:'asa-106021',family:'cisco-asa',raw:'ASA-4-106021: Deny TCP reverse path check from 192.168.2.2 to 10.10.10.10 on interface fw111'},
  {id:'netscreen-traffic',family:'netscreen',raw:'Jun  2 14:53:31 sample-host isg1000-A2: NetScreen device_id=0000011001000011 [Root]system-notification-00257(traffic): start_time="2015-11-11 10:02:10" duration=0 policy_id=244 service=https proto=6 src zone=Untrust dst zone=Trust action=Permit sent=0 rcvd=0 src=74.168.138.252 dst=72.72.72.72 src_port=1732 dst_port=443 session_id=488451 reason=Creation'},
  {id:'shorewall-kernel',family:'shorewall',raw:'May 28 17:23:25 myHost kernel: [3124658.791874] Shorewall:FORWARD:REJECT:IN=eth2 OUT=eth2 SRC=1.2.3.4 DST=192.168.0.10 LEN=141 TOS=0x00 PREC=0x00 TTL=63 ID=55251 PROTO=UDP SPT=5353 DPT=5335 LEN=121'},
  {id:'junos-hostless-close',family:'junos',raw:'Dec 17 08:05:30 RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 10.10.10.2/53836->10.10.10.1/22 junos-ssh 10.10.10.2/53836->10.10.10.1/22 None None 6 log-host-traffic untrust junos-host 5 78(6657) 122(13305) 45 UNKNOWN UNKNOWN N/A(N/A) ge-0/0/1.0 No'},
  {id:'junos-deny',family:'junos',raw:'Sep 29 23:49:20 SRX-1 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 10.0.0.1/54924->192.168.1.1/53 junos-dns-udp 17(0) default-deny(global) trust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 UNKNOWN policy deny'},
  {id:'bind-full',family:'bind',raw:'17-Feb-2018 23:06:56.326 queries: info: client 172.26.0.1#12345 (test.example.com): query: test.example.com IN A +E(0)K (172.26.0.3)'},
  {id:'bind-query-body',family:'bind',raw:'client @0x7f85b4026ed0 127.0.0.1#42520 (ci.elastic.co): query: ci.elastic.co IN A +E(0)K (35.193.103.164)'},
  {id:'squid-native',family:'squid',raw:'1525344856.899 16867 10.170.72.111 TCP_TUNNEL/200 6256 CONNECT logs.ap-southeast-2.amazonaws.com:443 - HIER_DIRECT/53.140.206.134 -'},
  {id:'httpd-combined',family:'httpd',raw:'83.149.9.216 - - [24/Feb/2015:23:13:42 +0000] "GET /presentations/image.png HTTP/1.1" 200 203023 "http://example.test/" "Mozilla/5.0"'},
  {id:'httpd-error',family:'httpd-error',raw:'[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] Premature end of script headers: example.com'},
  {id:'aws-classic-elb',family:'aws-elb',raw:'2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1"'},
  {id:'aws-s3-access',family:'aws-s3',raw:'79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - "GET /mybucket?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" -'},
  {id:'generic-syslog-file',family:'syslog',raw:'<14>Jun 24 10:32:02 win-host WinFileService Event: read, Path: /.DS_Store, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123'},
] as const;

describe('external Logstash Patterns Core holdout',()=>{
  it('measures current bounded-pipeline coverage without making the holdout an acceptance target',()=>{
    const rows=samples.map(sample=>{
      const parsed=parseSecurityInput(sample.raw);
      return {id:sample.id,family:sample.family,parsed:parsed.ok,kind:parsed.ok?parsed.kind:'error'};
    });
    const summary={
      total:rows.length,
      parsed:rows.filter(row=>row.parsed).length,
      failures:rows.filter(row=>!row.parsed).map(row=>row.id),
      byFamily:Object.fromEntries([...new Set(rows.map(row=>row.family))].map(family=>[family,{
        total:rows.filter(row=>row.family===family).length,
        parsed:rows.filter(row=>row.family===family&&row.parsed).length,
      }])),
    };
    console.log('LOGSTASH_EXTERNAL_HOLDOUT '+JSON.stringify(summary));
    expect(rows).toHaveLength(samples.length);
  });
});
