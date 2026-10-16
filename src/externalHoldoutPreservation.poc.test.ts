import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const samples=[
  {id:'netscreen',raw:'Jun  2 14:53:31 sample-host isg1000-A2: NetScreen device_id=0000011001000011 [Root]system-notification-00257(traffic): start_time="2015-11-11 10:02:10" duration=0 policy_id=244 service=https proto=6 src zone=Untrust dst zone=Trust action=Permit sent=0 rcvd=0 src=74.168.138.252 dst=72.72.72.72 src_port=1732 dst_port=443 session_id=488451 reason=Creation',must:['0000011001000011','2015-11-11 10:02:10','244','https','Untrust','Trust','Permit','74.168.138.252','72.72.72.72','1732','443','488451','Creation']},
  {id:'shorewall',raw:'May 28 17:23:25 myHost kernel: [3124658.791874] Shorewall:FORWARD:REJECT:IN=eth2 OUT=eth2 SRC=1.2.3.4 DST=192.168.0.10 LEN=141 TOS=0x00 PREC=0x00 TTL=63 ID=55251 PROTO=UDP SPT=5353 DPT=5335 LEN=121',must:['3124658.791874','FORWARD','REJECT','eth2','1.2.3.4','192.168.0.10','UDP','5353','5335']},
  {id:'junos',raw:'Sep 29 23:49:20 SRX-1 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 10.0.0.1/54924->192.168.1.1/53 junos-dns-udp 17(0) default-deny(global) trust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 UNKNOWN policy deny',must:['RT_FLOW_SESSION_DENY','10.0.0.1','54924','192.168.1.1','53','junos-dns-udp','default-deny(global)','ge-0/0/0.0']},
  {id:'squid',raw:'1525344856.899 16867 10.170.72.111 TCP_TUNNEL/200 6256 CONNECT logs.ap-southeast-2.amazonaws.com:443 - HIER_DIRECT/53.140.206.134 -',must:['1525344856.899','16867','10.170.72.111','TCP_TUNNEL','200','6256','CONNECT','logs.ap-southeast-2.amazonaws.com:443','HIER_DIRECT','53.140.206.134']},
  {id:'asa',raw:'ASA-2-106001: Inbound TCP connection denied from 192.168.2.2/43803 to 10.10.10.10/14322 flags SYN on interface out111',must:['ASA','2','106001','Inbound TCP connection denied','192.168.2.2','43803','10.10.10.10','14322','SYN','out111']},
  {id:'classic-elb',raw:'2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1"',must:['2014-02-15T23:39:43.945958Z','my-test-loadbalancer','192.168.131.39:2817','10.0.0.1:80','0.000073','0.001048','0.000057','200','29','GET','http://www.example.com:80/','HTTP/1.1']},
  {id:'bind-full',raw:'17-Feb-2018 23:06:56.326 queries: info: client 172.26.0.1#12345 (test.example.com): query: test.example.com IN A +E(0)K (172.26.0.3)',must:['17','Feb','2018','23:06:56.326','queries','info','172.26.0.1','12345','test.example.com','IN','A','+E(0)K','172.26.0.3']},
  {id:'bind-body',raw:'client @0x7f85b4026ed0 127.0.0.1#42520 (ci.elastic.co): query: ci.elastic.co IN A +E(0)K (35.193.103.164)',must:['7f85b4026ed0','127.0.0.1','42520','ci.elastic.co','IN','A','+E(0)K','35.193.103.164']},
  {id:'httpd-error',raw:'[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] Premature end of script headers: example.com',must:['Mon','Aug','31','16:27:04','2015','error','10.17.42.3','Premature end of script headers: example.com']},
  {id:'s3-access',raw:'79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - "GET /mybucket?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" -',must:['79a5','mybucket','06/Feb/2014:00:00:38 +0000','192.0.2.3','3E57427F3EXAMPLE','REST.GET.VERSIONING','GET','/mybucket?versioning','HTTP/1.1','200','113','7','S3Console/0.4']},
  {id:'comma-label-syslog',raw:'<14>Jun 24 10:32:02 win-host WinFileService Event: read, Path: /.DS_Store, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123',must:['14','Jun','24','10:32:02','win-host','WinFileService','read','/.DS_Store','File','6.00 KB','user@host','123.123.123.123']},
] as const;

function flattenedStrings(value:unknown,out:string[]=[]):string[]{
  if(typeof value==='string')out.push(value);
  else if(typeof value==='number'||typeof value==='boolean')out.push(String(value));
  else if(Array.isArray(value))value.forEach(item=>flattenedStrings(item,out));
  else if(value&&typeof value==='object')Object.values(value as Record<string,unknown>).forEach(item=>flattenedStrings(item,out));
  return out;
}

describe('external holdout source-preservation audit',()=>{
  it('keeps selected source values reachable in the structured result instead of counting shallow success',()=>{
    const rows=samples.map(sample=>{
      const parsed=parseSecurityInput(sample.raw);
      if(!parsed.ok)return {id:sample.id,missing:[...sample.must]};
      const corpus=flattenedStrings(parsed.events.map(event=>event.fields));
      const haystack=corpus.join('\n');
      return {id:sample.id,missing:sample.must.filter(value=>!haystack.includes(value))};
    });
    console.log('LOGSTASH_HOLDOUT_PRESERVATION '+JSON.stringify(rows));
    expect(rows.filter(row=>row.missing.length)).toEqual([]);
  });
});
