import {describe,expect,it} from 'vitest';
import {convertValue} from './parser';

describe('browser IP conversion matches RFC 4291 structural constraints',()=>{
  it.each([
    '2001:db8::1','::','::1','fe80::abcd','2001:db8:0:0:0:0:0:1',
    '::ffff:192.0.2.1','192.0.2.10','198.51.100.1',
  ])('accepts a valid literal %s without rewriting it',address=>{
    expect(convertValue(address,'ip')).toEqual({value:address});
  });
  it.each([
    ':::','2001:db8:::1','2001::db8::1','2001:db8:0:0:0:0:0:1:2',
    '2001:db8:0:0:0:0:1','2001:db8::gg','2001:db8::1%',
    '::ffff:192.0.2.999','::ffff:192.0.2.01','256.0.0.1','192.0.2',
  ])('rejects an invalid literal %s',address=>{
    expect(convertValue(address,'ip')).toEqual({error:'Expected valid IP address'});
  });
});
