import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseClassicElbAccessLog,parseS3AccessLog} from './awsLegacyAccess';

describe('AWS legacy access-log source grammars',()=>{
  it('parses classic ELB base/no-backend/TLS-suffix variants without shifting source positions',()=>{
    const samples=[
      '2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1"',
      '2015-04-10T08:11:09.865823Z prod-media 49.150.87.133:55128 - -1 -1 -1 408 - 1294336 0 "PUT https://media.example.test:443/videos/id HTTP/1.1"',
      '2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2',
    ];
    for(const raw of samples){
      const parsed=parseClassicElbAccessLog(raw);
      expect(parsed,raw).not.toBeNull();
      expect(extractGenericStructural(raw).errors,raw).toEqual([]);
    }
    expect(parseClassicElbAccessLog(samples[0])?.fields).toMatchObject({
      load_balancer:'my-test-loadbalancer',client_port:'192.168.131.39:2817',backend_port:'10.0.0.1:80',method:'GET',
    });
    expect(parseClassicElbAccessLog(samples[1])?.fields).toMatchObject({backend_port:'-',elb_status_code:'408',backend_status_code:'-'});
    expect(parseClassicElbAccessLog(samples[2])?.fields).toMatchObject({user_agent:'curl/7.38.0',ssl_protocol:'TLSv1.2'});
  });

  it('parses S3 access records with anonymous/requester variants and preserves trailing fields',()=>{
    const samples=[
      '79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - "GET /mybucket?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" -',
      '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket1 [06/Feb/2019:00:00:38 +0000] 192.0.2.3 arn:aws:iam::123456:user/test@example.test A1206F460EXAMPLE REST.GET.BUCKETPOLICY - "GET /awsexamplebucket1?policy HTTP/1.1" 404 NoSuchBucketPolicy 297 - 38 12 "-" "aws-sdk-java/1.11.590" - hostid SigV4 TLS_AES_128_GCM_SHA256 AuthHeader awsexamplebucket1.s3.amazonaws.com TLSv1.3 -',
    ];
    for(const raw of samples){
      const parsed=parseS3AccessLog(raw);
      expect(parsed,raw).not.toBeNull();
      expect(extractGenericStructural(raw).errors,raw).toEqual([]);
    }
    expect(parseS3AccessLog(samples[1])?.extra_fields.length).toBeGreaterThan(0);
  });

  it('rejects impossible dates, invalid endpoints/status, malformed request quotes, and shifted S3 fields',()=>{
    const elb='2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1"';
    const invalidElb=[
      elb.replace('2014-02-15','2014-02-30'),
      elb.replace('192.168.131.39:2817','999.0.0.1:2817'),
      elb.replace('192.168.131.39:2817','192.168.131.39:70000'),
      elb.replace(' 200 200 ',' 99 200 '),
      elb.replace('"GET http://www.example.com:80/ HTTP/1.1"','GET http://www.example.com:80/ HTTP/1.1'),
      elb.replace('"GET http://www.example.com:80/ HTTP/1.1"','"get / HTTP/1.1"'),
    ];
    expect(invalidElb.filter(raw=>parseClassicElbAccessLog(raw)!==null)).toEqual([]);

    const s3='79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - "GET /mybucket?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" -';
    const invalidS3=[
      s3.replace('06/Feb/2014','30/Feb/2014'),
      s3.replace('192.0.2.3','999.0.0.1'),
      s3.replace(' 200 - 113 ',' 99 - 113 '),
      s3.replace('"GET /mybucket?versioning HTTP/1.1"','GET /mybucket?versioning HTTP/1.1'),
      s3.replace('REST.GET.VERSIONING','bad operation'),
      s3.replace('3E57427F3EXAMPLE','bad!request'),
    ];
    expect(invalidS3.filter(raw=>parseS3AccessLog(raw)!==null)).toEqual([]);
  });
});
