import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

// Second independent selection from logstash-patterns-core specs at
// 74a4098582d3331a2b9b18c04d2446f2c0efb648. These variants are distinct
// from the first holdout selection.
const samples=[
  {id:'asa-106014',family:'cisco-asa',raw:'ASA-3-106014: Deny inbound icmp src fw111:10.10.10.10 dst fw111:10.10.10.11(type 8, code 0)'},
  {id:'asa-304001',family:'cisco-asa',raw:'ASA-6-304001: 10.20.30.40(DOMAIN\\login) Accessed URL 10.11.12.13:http://example.org/'},
  {id:'asa-313001',family:'cisco-asa',raw:'ASA-3-313001: Denied ICMP type=3, code=3 from 10.2.3.5 on interface Outside'},
  {id:'netscreen-deny',family:'netscreen',raw:'Mar 18 17:56:52 192.168.56.11 lowly_lizard: NetScreen device_id=netscreen2 [Root]system-notification-00257(traffic): start_time="2009-03-18 16:07:06" duration=0 policy_id=320001 service=msrpc Endpoint Mapper(tcp) proto=6 src zone=Null dst zone=self action=Deny sent=0 rcvd=16384 src=21.10.90.125 dst=23.16.1.1'},
  {id:'shorewall-drop',family:'shorewall',raw:'May 28 17:31:07 server Shorewall:net2fw:DROP:IN=eth1 OUT= MAC=00:02:b3:c7:2f:77 SRC=127.0.0.1 DST=1.2.3.4 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=6480 DF PROTO=TCP SPT=59088 DPT=8080 WINDOW=2920 RES=0x00 SYN URGP=0'},
  {id:'junos-create-hostless',family:'junos',raw:'Dec 17 08:04:45 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.10.10.2/53836->10.10.10.1/22 junos-ssh 10.10.10.2/53836->10.10.10.1/22 None None 6 log-host-traffic untrust junos-host 5 N/A(N/A) ge-0/0/1.0'},
  {id:'bind-ptr-full',family:'bind',raw:'30-Jun-2018 15:50:00.999 queries: info: client @0x7f64500020ef 192.168.10.48#60061 (91.2.10.170.in-addr.internal): query: 91.2.10.170.in-addr.internal IN PTR + (192.168.2.2)'},
  {id:'squid-get-direct',family:'squid',raw:'1525334330.556 3 120.65.1.1 TCP_REFRESH_MISS/200 2014 GET http://www.sample.com/hello.txt public-user DIRECT/www.sample.com text/plain'},
  {id:'squid-aborted',family:'squid',raw:'1426235912.366 16 192.168.3.50 TCP_MISS_ABORTED/000 0 GET http://garfield.com/comic/2015-03-13 - HIER_DIRECT/193.135.59.44 -'},
  {id:'httpd-email-user',family:'httpd',raw:'10.0.0.1 - username@example.com [07/Apr/2016:18:42:24 +0000] "GET /bar/foo/users/1/authenticate?token=x HTTP/1.1" 400 75 "" "Mozilla/5.0"'},
  {id:'httpd-status-dash',family:'httpd',raw:'83.149.9.216 - a.user [11/Jan/2020:23:05:27 +0100] "OPTIONS /remote.php/ HTTP/1.1" - 7908 "-" "monitoring-client"'},
  {id:'classic-elb-no-target',family:'aws-elb',raw:'2015-04-10T08:11:09.865823Z us-west-1-production-media 49.150.87.133:55128 - -1 -1 -1 408 - 1294336 0 "PUT https://media.example.test:443/videos/id HTTP/1.1"'},
  {id:'classic-elb-tls',family:'aws-elb',raw:'2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2'},
  {id:'s3-object',family:'aws-s3',raw:'79a5 mybucket [12/May/2014:07:54:01 +0000] 10.0.1.2 - 7ACC4BE89EXAMPLE REST.GET.OBJECT foo/bar.html "GET /foo/bar.html HTTP/1.1" 304 - - 1718 10 - "-" "Mozilla/5.0" -'},
  {id:'syslog-file-event',family:'syslog',raw:'<14>Jun 24 10:32:02 win-host WinFileService Event: read, Path: /test.dat, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123'},
] as const;

describe('external Logstash holdout round 2',()=>{
  it('measures unseen variants after the architectural improvements',()=>{
    const rows=samples.map(sample=>{
      const result=parseSecurityInput(sample.raw);
      return {id:sample.id,family:sample.family,parsed:result.ok,kind:result.ok?result.kind:'error'};
    });
    const summary={total:rows.length,parsed:rows.filter(row=>row.parsed).length,failures:rows.filter(row=>!row.parsed).map(row=>row.id)};
    console.log('LOGSTASH_EXTERNAL_HOLDOUT_R2 '+JSON.stringify(summary));
    expect(rows).toHaveLength(samples.length);
  });
});
