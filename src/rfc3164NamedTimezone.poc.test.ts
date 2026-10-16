import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

const samples=[
  {id:'classic-kst',raw:'<134>Oct 16 15:44:21 KST EDGE01 app: CEF:1|Vendor|EDR|1.0|42|Threat|8|src=192.0.2.10 dst=198.51.100.20',zone:'KST',host:'EDGE01'},
  {id:'classic-utc',raw:'<134>Oct 16 15:44:21 UTC fw01 app: {"event":"deny","src":"192.0.2.10","dst":"198.51.100.20"}',zone:'UTC',host:'fw01'},
  {id:'year-before-jst',raw:'<134>Oct 16 2026 15:44:21 JST proxy01 app: action=deny src=192.0.2.10 dst=198.51.100.20',zone:'JST',host:'proxy01'},
  {id:'year-after-cet',raw:'<134>Oct 16 15:44:21 2026 CET ids01 app: {"event":"alert","src":"192.0.2.11","dst":"198.51.100.21"}',zone:'CET',host:'ids01'},
  {id:'classic-pdt-no-pri',raw:'Oct 16 15:44:21 PDT edge-west app: LEEF:2.0|Vendor|Proxy|1|blocked|x5E|src=192.0.2.12^dst=198.51.100.22^act=deny',zone:'PDT',host:'edge-west'},
  {id:'classic-gmt-ip-host',raw:'<134>Oct 16 15:44:21 GMT 192.0.2.50 app: {"event":"login","src":"192.0.2.13","dst":"198.51.100.23"}',zone:'GMT',host:'192.0.2.50'},
] as const;

describe('RFC3164 named-timezone extension PoC',()=>{
  it('preserves approved named timezone IDs without converting their offsets',()=>{
    for(const sample of samples){
      const envelope=parseSyslogEnvelope(sample.raw);
      expect(envelope,sample.id).toMatchObject({timezone:sample.zone,hostname:sample.host});
      const parsed=extractGenericStructural(sample.raw);
      expect(parsed.errors,sample.id).toEqual([]);
      expect(parsed.fields.syslog,sample.id).toMatchObject({timezone:sample.zone,hostname:sample.host});
    }
  });

  it('does not mistake an allowlisted timezone word for a hostname when it is followed by an app tag',()=>{
    const raw='<134>Oct 16 15:44:21 UTC app: {"event":"alert","src":"192.0.2.10","dst":"198.51.100.20"}';
    const envelope=parseSyslogEnvelope(raw);
    expect(envelope).toMatchObject({hostname:'UTC',appname:'app'});
    expect(envelope?.timezone).toBeUndefined();
    const parsed=extractGenericStructural(raw);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.syslog).toMatchObject({hostname:'UTC',appname:'app'});
    expect((parsed.fields.syslog as Record<string,unknown>).timezone).toBeUndefined();
  });

  it('does not guess unknown or ambiguous uppercase tokens as timezone IDs',()=>{
    const unknown='<134>Oct 16 15:44:21 XYZ EDGE01 app: {"event":"alert","src":"192.0.2.1","dst":"198.51.100.1"}';
    const unknownEnvelope=parseSyslogEnvelope(unknown);
    expect(unknownEnvelope).toMatchObject({hostname:'XYZ'});
    expect(unknownEnvelope?.timezone).toBeUndefined();

    const ambiguous='<134>Oct 16 15:44:21 KST app: {"event":"alert"}';
    const ambiguousEnvelope=parseSyslogEnvelope(ambiguous);
    expect(ambiguousEnvelope).toMatchObject({hostname:'KST',appname:'app'});
    expect(ambiguousEnvelope?.timezone).toBeUndefined();
  });

  it('rejects invalid calendar values and structured-looking free text with no valid body grammar',()=>{
    const invalid=[
      '<134>Feb 30 2026 15:44:21 UTC EDGE01 app: {"event":"alert","src":"192.0.2.1","dst":"198.51.100.1"}',
      '<134>Oct 16 25:44:21 KST EDGE01 app: {"event":"alert","src":"192.0.2.1","dst":"198.51.100.1"}',
      '<134>Oct 16 15:44:21 KST EDGE01 ordinary free text',
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('RFC3164_NAMED_TZ_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
