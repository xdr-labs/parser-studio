import {describe,expect,it} from 'vitest';
import {isIpPortToken,isIpToken,isIpv4Token,isIpv6Token,isPortToken} from './networkTokens';

describe('shared network-token validator PoC',()=>{
  it('accepts bounded IPv4 and standard/compressed IPv6 forms',()=>{
    const valid=[
      '0.0.0.0','192.0.2.1','255.255.255.255',
      '::','::1','2001:db8::1','2001:db8:0:0:0:0:0:1','FE80::ABCD',
      '::ffff:192.0.2.128','2001:db8::192.0.2.33',
      '0:0:0:0:0:ffff:192.0.2.128',
    ];
    expect(valid.filter(value=>!isIpToken(value))).toEqual([]);
    expect(isIpv4Token('192.0.2.1')).toBe(true);
    expect(isIpv6Token('::ffff:192.0.2.128')).toBe(true);
  });

  it('rejects malformed address forms instead of normalizing them',()=>{
    const invalid=[
      '256.0.0.1','192.0.2','192.0.2.1.5','-1.2.3.4','1..2.3',
      '2001:db8:::1','2001::db8::1','2001:db8:1','12345::1',
      '::ffff:999.0.0.1','2001:db8::192.0.2.1:5','[2001:db8::1]',
      'fe80::1%eth0','not-an-ip','',
    ];
    expect(invalid.filter(isIpToken)).toEqual([]);
  });

  it('validates port boundaries and IP:port endpoint forms consistently',()=>{
    for(const value of ['0','1','22','443','65535'])expect(isPortToken(value)).toBe(true);
    for(const value of ['','-1','65536','99999','1.5','abc'])expect(isPortToken(value)).toBe(false);

    const valid=[
      '192.0.2.1:443',
      '2001:db8::10:51514',
      '::ffff:192.0.2.1:443',
      '[2001:db8::10]:443',
      '[::ffff:192.0.2.1]:443',
    ];
    expect(valid.filter(value=>!isIpPortToken(value))).toEqual([]);
    expect(isIpPortToken('-',true)).toBe(true);
  });

  it('rejects malformed endpoints and ambiguous non-address hosts',()=>{
    const invalid=[
      'example.com:443','192.0.2.1:65536','[2001:db8::1]443',
      '[2001:db8::1]:70000','2001:db8::zz:443','192.0.2.1',':443','-:443',
    ];
    expect(invalid.filter(value=>isIpPortToken(value))).toEqual([]);
    expect(isIpPortToken('-',false)).toBe(false);
  });
});
