import {describe,it,expect} from 'vitest';
import {inspectDeclaredForwarders,validForwarderConfig} from './declaredForwarder';

describe('User-declared Syslog relay header source review',()=>{
  const first='<134>Oct 19 10:02:03 relay01 fwd: {"message":"로그인 실패","src_ip":"192.0.2.4"}';
  const second='<134>Oct 19 10:02:04 relay01 fwd: {"message":"認証失敗","src_ip":"192.0.2.5"}';
  it('strips only an explicitly named relay and returns correct UTF-8 byte offsets',()=>{
    const cfg={maxHops:1 as const,relayHosts:['relay01']};
    expect(validForwarderConfig(cfg)).toBe(true);
    const x=inspectDeclaredForwarders(first,cfg);
    expect(x).toMatchObject({status:'UNWRAPPED',reason:'DECLARED_SYSLOG_RELAY'});
    expect(x.hops).toHaveLength(1);
    expect(x.payload).toBe('{"message":"로그인 실패","src_ip":"192.0.2.4"}');
    expect(new TextDecoder().decode(new TextEncoder().encode(first).slice(x.payloadStartByte)))
      .toBe(x.payload);
    const y=inspectDeclaredForwarders(second,cfg);
    expect(y.payload).toContain('認証失敗');
  });
  it('does not infer relay identity or strip undeclared forwarding hosts',()=>{
    expect(inspectDeclaredForwarders(first).status).toBe('DIRECT');
    expect(inspectDeclaredForwarders(first,{maxHops:1,relayHosts:['other']}))
      .toMatchObject({status:'DIRECT',payload:first});
  });
  it('supports two explicitly declared nested relay hops and denies hop overflow',()=>{
    const nested='<134>Oct 19 10:02:03 relay01 fwd: '+
      '<134>Oct 19 10:02:04 relay02 fwd: {"message":"警告"}';
    const cfg={maxHops:2 as const,relayHosts:['relay01','relay02']};
    const yes=inspectDeclaredForwarders(nested,cfg);
    expect(yes.status).toBe('UNWRAPPED');
    expect(yes.hops).toHaveLength(2);
    expect(yes.payload).toContain('警告');
    const no=inspectDeclaredForwarders(nested,{maxHops:1,relayHosts:['relay01','relay02']});
    expect(no).toMatchObject({status:'ABSTAIN_UNSAFE',reason:'DECLARED_RELAY_HOP_LIMIT_EXCEEDED'});
    expect(no.payload).toBe(nested);
  });
  it('rejects malformed relay profiles, control characters and unsafe source envelopes',()=>{
    expect(validForwarderConfig({maxHops:1,relayHosts:['a','a']})).toBe(false);
    expect(inspectDeclaredForwarders(first,{maxHops:2,relayHosts:['relay01','relay01']}).status)
      .toBe('ABSTAIN_UNSAFE');
    expect(inspectDeclaredForwarders(first+'\nsecond line',{maxHops:1,relayHosts:['relay01']}).status)
      .toBe('ABSTAIN_UNSAFE');
  });
});
