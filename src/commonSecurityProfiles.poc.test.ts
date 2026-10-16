import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseBindQueryMessage,parseCiscoIosSequenceSyslog,parseHttpAccessLog,parseLegacyOriginatorMessage,parseSquidAccessLog} from './commonSecurityProfiles';

describe('round 6 common security source grammars',()=>{
  it('keeps Cisco IOS sequence/timestamp envelopes bounded',()=>{
    const valid=[
      '<189>12345: Oct 16 15:44:21.123 KST: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]',
      '<189>321: Feb 29 23:59:59.999 +0900: %SYS-5-CONFIG_I: Configured from console',
    ];
    expect(valid.every(raw=>parseCiscoIosSequenceSyslog(raw)!==null)).toBe(true);
    const invalid=[
      '<192>12345: Oct 16 15:44:21 KST: %SYS-5-CONFIG_I: bad pri',
      '<189>12345: Foo 16 15:44:21 KST: %SYS-5-CONFIG_I: bad month',
      '<189>12345: Oct 32 15:44:21 KST: %SYS-5-CONFIG_I: bad day',
      '<189>12345: Oct 16 25:44:21 KST: %SYS-5-CONFIG_I: bad hour',
      '<189>12345: Oct 16 15:44:21 +2500: %SYS-5-CONFIG_I: bad zone',
      '<189>12345: Oct 16 15:44:21 KST: %SYS-9-BAD: bad severity',
      '<189>12345: Oct 16 15:44:21 KST: malformed body',
    ];
    const accepted=invalid.filter(raw=>parseCiscoIosSequenceSyslog(raw)!==null);
    console.log('CISCO_IOS_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });

  it('parses common/combined HTTP access logs and rejects malformed boundary values',()=>{
    const valid=[
      '192.0.2.10 - alice [16/Oct/2026:15:44:21 +0900] "GET /login HTTP/1.1" 403 123 "-" "Mozilla/5.0"',
      '2001:db8::10 - - [29/Feb/2028:23:59:59 +0000] "POST /api HTTP/2.0" 201 -',
    ];
    expect(valid.every(raw=>parseHttpAccessLog(raw)!==null)).toBe(true);
    const invalid=[
      '999.0.0.1 - - [16/Oct/2026:15:44:21 +0000] "GET / HTTP/1.1" 200 1',
      '192.0.2.1 - - [30/Feb/2026:15:44:21 +0000] "GET / HTTP/1.1" 200 1',
      '192.0.2.1 - - [16/Oct/2026:15:44:21 +2500] "GET / HTTP/1.1" 200 1',
      '192.0.2.1 - - [16/Oct/2026:15:44:21 +0000] "get / HTTP/1.1" 200 1',
      '192.0.2.1 - - [16/Oct/2026:15:44:21 +0000] "GET / HTTP/1.1" 999 1',
      '192.0.2.1 - - [16/Oct/2026:15:44:21 +0000] "GET / HTTP/1.1 200 1',
    ];
    expect(invalid.filter(raw=>parseHttpAccessLog(raw)!==null)).toEqual([]);
  });

  it('parses Squid native access records and rejects malformed network/status tokens',()=>{
    const valid=[
      '1792152264.123 321 192.0.2.10 TCP_DENIED/403 1234 GET https://example.test/login - HIER_NONE/- text/html',
      '1792152265.456 12 2001:db8::10 TCP_TUNNEL/200 0 CONNECT example.test:443 alice HIER_DIRECT/198.51.100.20 -',
    ];
    expect(valid.every(raw=>parseSquidAccessLog(raw)!==null)).toBe(true);
    const invalid=[
      'bad 321 192.0.2.10 TCP_DENIED/403 1234 GET https://example.test/ - HIER_NONE/- text/html',
      '1792152264.1 321 999.0.0.1 TCP_DENIED/403 1234 GET https://example.test/ - HIER_NONE/- text/html',
      '1792152264.1 321 192.0.2.10 TCP_DENIED/999 1234 GET https://example.test/ - HIER_NONE/- text/html',
      '1792152264.1 321 192.0.2.10 bad/403 1234 GET https://example.test/ - HIER_NONE/- text/html',
      '1792152264.1 321 192.0.2.10 TCP_DENIED/403 x GET https://example.test/ - HIER_NONE/- text/html',
      '1792152264.1 321 192.0.2.10 TCP_DENIED/403 1234 get https://example.test/ - HIER_NONE/- text/html',
    ];
    expect(invalid.filter(raw=>parseSquidAccessLog(raw)!==null)).toEqual([]);
  });

  it('parses BIND query messages only with valid endpoints and matching query identity',()=>{
    const valid=[
      'client @0x7f1a 192.0.2.10#51514 (example.test): query: example.test IN A +E(0)K (192.0.2.53)',
      'client 2001:db8::10#53 (example.test): query: example.test IN AAAA + (2001:db8::53)',
    ];
    expect(valid.every(raw=>parseBindQueryMessage(raw)!==null)).toBe(true);
    const invalid=[
      'client 999.0.0.1#51514 (example.test): query: example.test IN A + (192.0.2.53)',
      'client 192.0.2.10#70000 (example.test): query: example.test IN A + (192.0.2.53)',
      'client 192.0.2.10#51514 (other.test): query: example.test IN A + (192.0.2.53)',
      'client 192.0.2.10#51514 (example.test): query: example.test BAD A + (192.0.2.53)',
      'client 192.0.2.10#51514 (example.test): query: example.test IN A + (999.0.0.1)',
    ];
    expect(invalid.filter(raw=>parseBindQueryMessage(raw)!==null)).toEqual([]);
  });

  it('parses legacy Originator structured prefixes and blocks unsafe parameter keys',()=>{
    const valid='[Originator@6876 sub=Vimsvc.ha-eventmgr opID=abc-123] Event 42: User admin logged in';
    expect(parseLegacyOriginatorMessage(valid)).toMatchObject({structured_id:'Originator@6876',message:'Event 42: User admin logged in'});
    const invalid=[
      '[Originator sub=Vimsvc] Event 1',
      '[Originator@6876 constructor=bad sub=Vimsvc] Event 1',
      '[Originator@6876] Event 1',
      '[Originator@6876 sub="unterminated] Event 1',
    ];
    expect(invalid.filter(raw=>parseLegacyOriginatorMessage(raw)!==null)).toEqual([]);
  });

  it('keeps all round-6 representative events structured through the public engine',()=>{
    const samples=[
      '<189>12345: Oct 16 15:44:21.123 KST: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]',
      '<189>Oct 16 15:44:21 router01 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]',
      '192.0.2.10 - alice [16/Oct/2026:15:44:21 +0900] "GET /login HTTP/1.1" 403 123 "-" "Mozilla/5.0"',
      '1792152264.123 321 192.0.2.10 TCP_DENIED/403 1234 GET https://example.test/login - HIER_NONE/- text/html',
      '<30>Oct 16 15:44:21 dns01 named[1234]: client 192.0.2.10#51514 (example.test): query: example.test IN A + (192.0.2.53)',
      '<166>Oct 16 15:44:21 esxi01 hostd[12345]: [Originator@6876 sub=Vimsvc.ha-eventmgr opID=abc-123] Event 42: User admin logged in',
    ];
    expect(samples.every(raw=>extractGenericStructural(raw).errors.length===0)).toBe(true);
  });
});
