import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

describe('RFC5424 NILVALUE boundary PoC',()=>{
  it('keeps all header NILVALUE fields absent while parsing structured bodies',()=>{
    const samples=[
      '<34>1 - - - - - - CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.1 dst=198.51.100.1',
      '<34>1 - - - - - - LEEF:2.0|Vendor|NDR|1|dns|x5E|src=192.0.2.1^dst=198.51.100.1^act=deny',
      '<34>1 - - - - - - {"event":"alert","src":"192.0.2.1","dst":"198.51.100.1"}',
    ];
    for(const raw of samples){
      const envelope=parseSyslogEnvelope(raw);
      expect(envelope).not.toBeNull();
      expect(envelope?.variant).toBe('rfc5424');
      expect(envelope?.timestamp).toBeUndefined();
      expect(envelope?.hostname).toBeUndefined();
      expect(envelope?.appname).toBeUndefined();
      expect(envelope?.procid).toBeUndefined();
      expect(envelope?.msgid).toBeUndefined();
      expect(envelope?.structuredData).toBe('-');
      const parsed=extractGenericStructural(raw);
      expect(parsed.errors).toEqual([]);
      expect(parsed.fields).toHaveProperty('body');
    }
  });

  it('preserves partial NILVALUE and structured-data elements without inventing absent fields',()=>{
    const raw='<165>1 2026-10-16T12:34:56.123Z - sensor - EVT42 [meta@32473 tenant="blue" tenant="green"][trace@32473 id="abc\\]123"] {"event":"dns","src":"2001:db8::10"}';
    const envelope=parseSyslogEnvelope(raw);
    expect(envelope).toMatchObject({variant:'rfc5424',timestamp:'2026-10-16T12:34:56.123Z',appname:'sensor',msgid:'EVT42'});
    expect(envelope?.hostname).toBeUndefined();
    expect(envelope?.procid).toBeUndefined();
    expect(envelope?.structuredDataElements).toEqual([
      {id:'meta@32473',params:{tenant:['blue','green']}},
      {id:'trace@32473',params:{id:'abc]123'}},
    ]);
    const parsed=extractGenericStructural(raw);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.syslog).toMatchObject({appname:'sensor',msgid:'EVT42'});
    expect(parsed.fields.body).toMatchObject({event:'dns',src:'2001:db8::10'});
  });

  it('accepts a strict RFC5424 envelope with no MSG but does not mislabel it as structured body success',()=>{
    const raw='<13>1 - host app 123 MSG42 -';
    const envelope=parseSyslogEnvelope(raw);
    expect(envelope).toMatchObject({variant:'rfc5424',hostname:'host',appname:'app',procid:'123',msgid:'MSG42',structuredData:'-',message:''});
    const parsed=extractGenericStructural(raw);
    expect(parsed.errors.length).toBeGreaterThan(0);
  });

  it('rejects malformed NILVALUE boundaries and invalid printable header tokens',()=>{
    const invalid=[
      '<34>1 -- - - - - - CEF:1|V|P|1|1|N|1|src=192.0.2.1',
      '<34>1 - host name app 123 MSG - body',
      '<34>1 - host app 123 MSG -- body',
      '<34>1 - host app 123 MSG -body',
      '<34>1 - host app 123 MSG [id key="unterminated] body',
      '<34>1 - host app 123 MSG [constructor x="1"] body',
      '<34>0 - host app 123 MSG - body',
    ];
    const envelopeAccepted=invalid.filter(raw=>parseSyslogEnvelope(raw)!==null);
    const structuredAccepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('RFC5424_NILVALUE_INVALID '+JSON.stringify({total:invalid.length,envelopeAccepted,structuredAccepted}));
    expect(envelopeAccepted).toEqual([]);
    expect(structuredAccepted).toEqual([]);
  });
});
