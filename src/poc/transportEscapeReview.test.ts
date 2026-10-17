import {describe,expect,it} from 'vitest';
import {observedWireShape,reviewEscapeContract,
  type DeclaredWireFormat} from './transportEscapeReview';
import {conservativeKvLocatedFields} from './conservativeKvUtf8Span';

const check=(raw:string,declared:DeclaredWireFormat,version:string|null)=>
  reviewEscapeContract({raw,declared,deviceVersion:version});
const fortinetRaw=String.raw`<14>date=2026-10-17 msg="slash \? stays" count=1`;
const fortinetCef=String.raw`Oct 17 12:34:56 edge CEF:0|Fortinet|Fortigate|7.2.7|1|event|4|cs1=a\=b`;
const rfc5424=String.raw`<165>1 2026-10-17T12:00:00Z host app 123 ID47 [example@123 foo="a\]b" quote="a\"b"] hello`;
describe('transport- and manufacturer-specific escape scope stays non-promoted',()=>{
  it('distinguishes raw KV, CEF, RFC5424 SD and unknown message envelopes',()=>{
    expect(observedWireShape(fortinetRaw)).toBe('KV_LEXICAL');
    expect(observedWireShape(fortinetCef)).toBe('CEF_HEADER');
    expect(observedWireShape(rfc5424)).toBe('RFC5424_HEADER');
    expect(observedWireShape('arbitrary prose')).toBe('OTHER');
  });
  it('does not give CEF extension escapes to FGT raw KV events',()=>{
    const result=check(fortinetRaw,'FORTIOS_CEF','7.2.7');
    expect(result.disposition).toBe('FORMAT_CONFLICT_UNSCORABLE');
    expect(result.canDecodeVendorEscapes).toBe(false);
    expect(conservativeKvLocatedFields(fortinetRaw)?.fields.msg)
      .toBe(String.raw`slash \? stays`);
  });
  it('recognizes the documented FortiOS CEF *scope*, without certifying wire decoding',()=>{
    const result=check(fortinetCef,'FORTIOS_CEF','7.2.7');
    expect(result.evidence).toBe('FORTIOS_7_2_CEF_EXTENSION_DOCUMENTED');
    expect(result.manufacturerEscapeSemantics).toBe('NOT_CERTIFIED');
    expect(result.canAutoPromote).toBe(false);
    expect(conservativeKvLocatedFields(fortinetCef)).toBeNull();
  });
  it('keeps RFC5424 SD and its escapes out of the generic KV decoder',()=>{
    const result=check(rfc5424,'RFC5424_SD','rfc5424');
    expect(result.evidence).toBe('RFC5424_STRUCTURED_DATA_DOCUMENTED');
    expect(result.canDecodeVendorEscapes).toBe(false);
    expect(conservativeKvLocatedFields(rfc5424)).toBeNull();
  });
  it('does not infer a manufacturer contract from configurable transport mode',()=>{
    const sonic=check('msg="hello" second=ok','SONICOS_ENHANCED','7.1');
    const sophos=check('log_id=123 action=allow','SOPHOS_STANDARD','20.0');
    for(const result of [sonic,sophos]){
      expect(result.evidence).toBe('VENDOR_FORMAT_OPTIONS_ONLY');
      expect(result.canAutoPromote).toBe(false);
    }
  });
  it('refuses unknown version, unknown transport and source format conflicts',()=>{
    expect(check(fortinetCef,'FORTIOS_CEF',null).disposition)
      .toBe('VERSION_OR_WIRE_UNSCORABLE');
    expect(check(fortinetCef,'FORTIOS_RAW_KV','7.2.7').disposition)
      .toBe('FORMAT_CONFLICT_UNSCORABLE');
    expect(check(fortinetRaw,'UNKNOWN','7.2.7').disposition)
      .toBe('VERSION_OR_WIRE_UNSCORABLE');
    expect(check(fortinetRaw,'FORTIOS_RAW_KV','7.2.7').evidence)
      .toBe('UNDEFINED_FOR_VERSION_OR_WIRE');
  });
});
