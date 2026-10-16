import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

describe('Syslog named-zone IPv6 hostname boundary PoC',()=>{
  it('parses named-zone BSD variants when HOSTNAME is an IPv6 literal',()=>{
    const samples=[
      {id:'classic',raw:'<134>Oct 16 15:44:21 KST 2001:db8::10 CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.1 dst=198.51.100.1',variant:'rfc3164_tz'},
      {id:'year-before',raw:'<134>Oct 16 2026 15:44:21 KST 2001:db8::11 {"event":"alert","src":"192.0.2.1"}',variant:'rfc3164_year_before_time_tz'},
      {id:'year-after',raw:'<134>Oct 16 15:44:21 2026 JST 2001:db8::12 LEEF:2.0|Vendor|NDR|1|dns|x5E|src=192.0.2.1^dst=198.51.100.1^act=deny',variant:'rfc3164_year_after_time_tz'},
    ] as const;
    const rows=samples.map(sample=>{
      const envelope=parseSyslogEnvelope(sample.raw);
      const parsed=extractGenericStructural(sample.raw);
      return {sample,envelope,parsed};
    });
    console.log('SYSLOG_IPV6_HOST_NAMED_ZONE '+JSON.stringify(rows.map(row=>({
      id:row.sample.id,variant:row.envelope?.variant,timezone:row.envelope?.timezone,hostname:row.envelope?.hostname,structured:row.parsed.errors.length===0,
    }))));
    for(const row of rows){
      expect(row.envelope?.variant,row.sample.id).toBe(row.sample.variant);
      expect(row.envelope?.hostname,row.sample.id).toMatch(/^2001:db8::/);
      expect(row.envelope?.timezone,row.sample.id).toMatch(/^(KST|JST)$/);
      expect(row.parsed.errors,row.sample.id).toEqual([]);
    }
  });

  it('keeps unknown uppercase tokens as hostname instead of inventing a timezone',()=>{
    const raw='<134>Oct 16 15:44:21 FOO 2001:db8::10 CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.1';
    const envelope=parseSyslogEnvelope(raw);
    expect(envelope).toMatchObject({variant:'rfc3164',hostname:'FOO'});
    expect(envelope?.timezone).toBeUndefined();
  });
});
