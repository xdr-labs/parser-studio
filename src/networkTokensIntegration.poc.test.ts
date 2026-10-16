import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSshdMessage} from './commonSecurityProfiles';
import {parseFortinetKvBody} from './applianceSecurityProfiles';
import {parseVpcFlowLogV2} from './awsVpcFlow';
import {parseAlbAccessLog} from './awsAlbAccess';
import {parseClassicElbAccessLog,parseS3AccessLog} from './awsLegacyAccess';
import {convertValue} from './parser';

const mapped='::ffff:192.0.2.10';
const badMapped='::ffff:999.0.0.1';

const juniper=(src:string,dst:string)=>
  'Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created '+
  src+'/40275->'+dst+'/161 None '+src+'/40275->'+dst+'/161 None None 17 allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255';

const albBase=[
  'https','2026-10-16T15:44:21.123456Z','app/my-loadbalancer/50dc6c495c0c9188',
  '192.0.2.10:51514','10.0.0.10:443','0.001','0.002','0.003','200','200','123','456',
  '"GET https://www.example.test:443/login HTTP/1.1"','"Mozilla/5.0 Test Agent"',
  'TLS_AES_128_GCM_SHA256','TLSv1.3',
  'arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067',
  '"Root=1-abcdef1234567890"','"www.example.test"',
  '"arn:aws:acm:ap-northeast-2:123456789012:certificate/abc123"','1',
  '2026-10-16T15:44:21.100000Z','"forward"','"-"','"-"','"10.0.0.10:443"','"200"','"-"','"-"',
  'TID_1234abcd5678ef90','"-"','"-"','"-"','-','-','-',
].join(' ');

const classicElb='2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.0.2.10:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1"';
const s3='79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.10 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - "GET /mybucket?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" -';

describe('shared network-token integration PoC',()=>{
  it('accepts the same IPv4-mapped IPv6 source across reviewed parser families',()=>{
    const results=[
      extractGenericStructural(juniper(mapped,'2001:db8::20')).errors.length===0,
      parseSshdMessage('Accepted password for root from '+mapped+' port 22 ssh2')!==null,
      parseFortinetKvBody('date=2026-10-16 time=12:00:00 devname="FW01" devid="FG3000" logid="100000001" type="traffic" srcip='+mapped+' dstip=2001:db8::20 srcport=51514 dstport=443')!==null,
      parseVpcFlowLogV2('2 123456789012 eni-0abc1234def567890 '+mapped+' 2001:db8::20 51514 443 6 10 8400 1760000000 1760000060 ACCEPT OK')!==null,
      parseAlbAccessLog(albBase.replace('192.0.2.10:51514',mapped+':51514'))!==null,
      parseClassicElbAccessLog(classicElb.replace('192.0.2.10:2817',mapped+':2817'))!==null,
      parseS3AccessLog(s3.replace('192.0.2.10',mapped))!==null,
    ];
    console.log('SHARED_NETWORK_MAPPED_IPV6 '+JSON.stringify({total:results.length,accepted:results.filter(Boolean).length}));
    expect(results).toEqual([true,true,true,true,true,true,true]);
  });

  it('rejects the same malformed embedded IPv4 across parser families',()=>{
    const results=[
      extractGenericStructural(juniper(badMapped,'2001:db8::20')).errors.length===0,
      parseSshdMessage('Accepted password for root from '+badMapped+' port 22 ssh2')!==null,
      parseFortinetKvBody('date=2026-10-16 time=12:00:00 devname="FW01" devid="FG3000" logid="100000001" type="traffic" srcip='+badMapped+' dstip=2001:db8::20 srcport=51514 dstport=443')!==null,
      parseVpcFlowLogV2('2 123456789012 eni-0abc1234def567890 '+badMapped+' 2001:db8::20 51514 443 6 10 8400 1760000000 1760000060 ACCEPT OK')!==null,
      parseAlbAccessLog(albBase.replace('192.0.2.10:51514',badMapped+':51514'))!==null,
      parseClassicElbAccessLog(classicElb.replace('192.0.2.10:2817',badMapped+':2817'))!==null,
      parseS3AccessLog(s3.replace('192.0.2.10',badMapped))!==null,
    ];
    console.log('SHARED_NETWORK_INVALID_MAPPED_IPV6 '+JSON.stringify({total:results.length,accepted:results.filter(Boolean).length}));
    expect(results).toEqual([false,false,false,false,false,false,false]);
  });

  it('keeps endpoint source contracts while sharing the underlying IP validation',()=>{
    expect(parseAlbAccessLog(albBase.replace('192.0.2.10:51514','['+mapped+']:51514'))).not.toBeNull();
    expect(parseClassicElbAccessLog(classicElb.replace('192.0.2.10:2817','['+mapped+']:2817'))).toBeNull();
    expect(parseClassicElbAccessLog(classicElb.replace('192.0.2.10:2817',mapped+':2817'))).not.toBeNull();
  });

  it('uses the same network primitive during field type conversion',()=>{
    expect(convertValue(mapped,'ip')).toEqual({value:mapped});
    expect(convertValue(badMapped,'ip')).toEqual({error:'Expected valid IP address'});
    expect(convertValue('65535','port')).toEqual({value:65535});
    expect(convertValue('65536','port')).toEqual({error:'Expected port 0..65535'});
    expect(convertValue('000000','port')).toEqual({error:'Expected port 0..65535'});
  });
});
