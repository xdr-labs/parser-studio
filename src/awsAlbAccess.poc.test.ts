import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseAlbAccessLog} from './awsAlbAccess';

const base=[
  'https',
  '2026-10-16T15:44:21.123456Z',
  'app/my-loadbalancer/50dc6c495c0c9188',
  '192.0.2.10:51514',
  '10.0.0.10:443',
  '0.001','0.002','0.003',
  '200','200','123','456',
  '"GET https://www.example.test:443/login HTTP/1.1"',
  '"Mozilla/5.0 Test Agent"',
  'TLS_AES_128_GCM_SHA256','TLSv1.3',
  'arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067',
  '"Root=1-abcdef1234567890"',
  '"www.example.test"',
  '"arn:aws:acm:ap-northeast-2:123456789012:certificate/abc123"',
  '1',
  '2026-10-16T15:44:21.100000Z',
  '"forward"','"-"','"-"','"10.0.0.10:443"','"200"','"-"','"-"',
  'TID_1234abcd5678ef90',
  '"-"','"-"','"-"',
  '-', '-', '-',
].join(' ');

describe('AWS ALB access-log structural PoC',()=>{
  it('parses documented positional fields standalone and behind Syslog',()=>{
    const parsed=parseAlbAccessLog(base);
    expect(parsed).not.toBeNull();
    expect(parsed?.fields).toMatchObject({
      type:'https',
      time:'2026-10-16T15:44:21.123456Z',
      client_port:'192.0.2.10:51514',
      target_port:'10.0.0.10:443',
      elb_status_code:'200',target_status_code:'200',
      request_line:'GET https://www.example.test:443/login HTTP/1.1',
      user_agent:'Mozilla/5.0 Test Agent',
      actions_executed:'forward',
    });
    expect(parsed?.extra_fields).toEqual([]);

    const direct=extractGenericStructural(base);
    expect(direct.errors).toEqual([]);
    expect(direct.fields.aws_alb_access).toEqual(parsed);

    const wrapped=extractGenericStructural('<134>2026-10-16T15:44:21Z ALB01 alb: '+base);
    expect(wrapped.errors).toEqual([]);
    expect(wrapped.fields.aws_alb_access).toEqual(parsed);
  });

  it('accepts WAF-blocked/no-target shape and trailing future fields without shifting known fields',()=>{
    const waf=base
      .replace('10.0.0.10:443','-')
      .replace('0.002','-1')
      .replace('200 200 123 456','403 - 123 456')
      .replace('"forward"','"waf"')
      .replace('"10.0.0.10:443"','"-"')
      .replace('"200"','"-"')+' - future-field';
    const parsed=parseAlbAccessLog(waf);
    expect(parsed).not.toBeNull();
    expect(parsed?.fields).toMatchObject({target_port:'-',elb_status_code:'403',target_status_code:'-',actions_executed:'waf'});
    expect(parsed?.extra_fields).toEqual(['-','future-field']);
  });

  it('accepts bare IPv6 client:port and preserves request/user-agent quoting semantics',()=>{
    const ipv6=base.replace('192.0.2.10:51514','2001:db8::10:51514');
    const parsed=parseAlbAccessLog(ipv6);
    expect(parsed).not.toBeNull();
    expect(parsed?.fields.client_port).toBe('2001:db8::10:51514');
  });

  it('rejects malformed core positions and quote-boundary drift',()=>{
    const invalid=[
      base.replace(/^https /,'ftp '),
      base.replace('2026-10-16T15:44:21.123456Z','2026-02-30T15:44:21Z'),
      base.replace('192.0.2.10:51514','999.0.0.1:51514'),
      base.replace('192.0.2.10:51514','192.0.2.10:70000'),
      base.replace(' 200 200 123 456 ',' 99 200 123 456 '),
      base.replace('"GET https://www.example.test:443/login HTTP/1.1"','"get https://www.example.test/login HTTP/1.1"'),
      base.replace('"GET https://www.example.test:443/login HTTP/1.1"','GET https://www.example.test:443/login HTTP/1.1'),
      base.replace('arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067','bad-arn'),
      base.replace('2026-10-16T15:44:21.100000Z','not-a-time'),
      base.replace('"Mozilla/5.0 Test Agent"','"unterminated'),
    ];
    const accepted=invalid.filter(raw=>parseAlbAccessLog(raw)!==null);
    console.log('AWS_ALB_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
