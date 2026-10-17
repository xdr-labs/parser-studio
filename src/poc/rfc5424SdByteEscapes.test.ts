import {describe,expect,it} from 'vitest';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';

const frame='<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 ';
const asBytes=(s:string)=>new TextEncoder().encode(s);
const backslash='\\';
const slice=(raw:string,start:number,end:number)=>
  new TextDecoder('utf-8',{fatal:true}).decode(asBytes(raw).slice(start,end));

describe('RFC5424 byte-faithful SD-PARAM escapes - standards scope only',()=>{
  it('follows the official two-element structured-data RFC example',()=>{
    const sd='[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]'+
      '[examplePriority@32473 class="high"]';
    const result=rfc5424SdByteEscapes(asBytes(frame+sd));
    expect(result?.elements.map(e=>[e.id,e.params.length])).toEqual([
      ['exampleSDID@32473',3],['examplePriority@32473',1],
    ]);
    expect(result?.structuredDataStart).toBe(asBytes(frame).length);
    expect(result?.structuredDataEnd).toBe(asBytes(frame+sd).length);
    expect(result?.messageStart).toBeNull();
    expect(result?.canAutoPromote).toBe(false);
    expect(result?.deviceImplementation).toBe('NOT_CERTIFIED');
  });

  it('decodes only quoted, backslash and right bracket SD escapes',()=>{
    const sd='[example@32473 bracket="one'+backslash+']two"'+
      ' quote="say '+backslash+'"yes'+backslash+'""'+
      ' path="A:'+backslash+backslash+'B" unknown="literal'+backslash+'q"]';
    const raw=frame+sd;
    const result=rfc5424SdByteEscapes(asBytes(raw));
    expect(result?.elements).toHaveLength(1);
    expect(result?.elements[0]?.params.map(p=>p.decodedValue)).toEqual([
      'one]two','say "yes"','A:\\B','literal\\q',
    ]);
    expect(result?.elements[0]?.params.map(p=>p.unrecognizedEscapes)).toEqual([0,0,0,1]);
    const p=result!.elements[0]!.params[0]!;
    expect(slice(raw,p.rawValueStart,p.rawValueEnd)).toBe('one'+backslash+']two');
    expect(p.rawValueEnd-p.rawValueStart).toBe(asBytes('one'+backslash+']two').length);
  });

  it('calculates UTF-8 byte ranges after multi-byte parameter values',()=>{
    const raw=frame+'[example@32473 a="€😀" b="after"]';
    const result=rfc5424SdByteEscapes(asBytes(raw))!;
    const [a,b]=result.elements[0]!.params;
    expect(a?.decodedValue).toBe('€😀');
    expect(b?.rawValueStart).toBe(asBytes(frame+'[example@32473 a="€😀" b="').length);
    expect(slice(raw,b!.rawValueStart,b!.rawValueEnd)).toBe('after');
  });

  it('allows repeated SD-PARAM keys while refusing duplicate SD-IDs',()=>{
    const raw=frame+'[example@32473 same="one" same="two"]';
    const result=rfc5424SdByteEscapes(asBytes(raw));
    expect(result?.elements[0]?.params.map(p=>p.decodedValue)).toEqual(['one','two']);
    expect(rfc5424SdByteEscapes(asBytes(
      frame+'[example@32473 a="1"][example@32473 b="2"]'))).toBeNull();
  });

  it('keeps NILVALUE and any MSG bytes outside the decoder scope',()=>{
    const raw=frame+'- payload\\q';
    const result=rfc5424SdByteEscapes(asBytes(raw));
    expect(result?.elements).toHaveLength(0);
    expect(slice(raw,result!.messageStart!,asBytes(raw).length)).toBe('payload\\q');
    const message=frame+'[example@32473 x="value"] free\\]text';
    const scanned=rfc5424SdByteEscapes(asBytes(message))!;
    expect(scanned.elements[0]!.params[0]!.decodedValue).toBe('value');
    expect(slice(message,scanned.messageStart!,asBytes(message).length))
      .toBe('free\\]text');
  });

  it('does not mistake native KV, CEF or a version-only prefix for RFC5424',()=>{
    for(const raw of [
      '<14>date=2026-10-17 msg="FGT" count=1',
      'Oct 17 12:00:00 fw CEF:0|Fortinet|Fortigate|7.2|1|Log|3|act=allow',
      '<165>2 2003-10-11T22:14:15.003Z host app - ID47 [example@32473 a="v"]',
    ])expect(rfc5424SdByteEscapes(asBytes(raw))).toBeNull();
  });

  it('rejects malformed quote, bracket, SD-NAME and corrupt UTF-8',()=>{
    for(const sd of [
      '[x@32473 a="unterminated]',
      '[x@32473 a="unescaped]bracket"]',
      '[ x@32473 a="v"]',
      '[x@32473 a="v" bad="unterminated]',
      '[x@32473 a="v"]unexpected',
      '[x@32473 a="v"b="w"]',
      '[x@32473 a=v]',
      '[x@32473 a="v" ',
      '[x@32473 a="v"]'+'[x@32473 b="v"]',
    ])expect(rfc5424SdByteEscapes(asBytes(frame+sd))).toBeNull();
    expect(rfc5424SdByteEscapes(new Uint8Array([60,49,62,49,32,255]))).toBeNull();
    expect(rfc5424SdByteEscapes(asBytes(frame+'[x@32473 a="v"]'.repeat(10000))))
      .toBeNull();
  });

  it('does not interpret unknown escaped punctuation as an SD control',()=>{
    const raw=frame+'[x@32473 first="x'+backslash+'?y" second="z'+backslash+'=w"]';
    const result=rfc5424SdByteEscapes(asBytes(raw))!;
    expect(result.elements[0]!.params.map(p=>p.decodedValue))
      .toEqual(['x\\?y','z\\=w']);
    expect(result.elements[0]!.params.every(p=>p.unrecognizedEscapes===1)).toBe(true);
  });
  it('checks RFC5424 header bounds before interpreting any SD parameter escape',()=>{
    const suffix='[example@32473 a="value"]';
    const from=(ts:string)=>frame.replace('2003-10-11T22:14:15.003Z',ts)+suffix;
    expect(rfc5424SdByteEscapes(
      asBytes(from('2024-02-29T23:59:59.000003+12:45')))?.elements).toHaveLength(1);
    for(const timestamp of [
      '2026-02-29T22:14:15Z','2003-13-01T22:14:15Z',
      '2026-10-17T24:00:00Z','2026-10-17T23:60:00Z',
      '2026-10-17T23:59:60Z','2026-10-17T23:59:59+24:00',
      '2026-10-17T23:59:59.0000009Z',
    ])expect(rfc5424SdByteEscapes(asBytes(from(timestamp)))).toBeNull();
    for(const prefix of ['<000>','<019>','<192>']){
      const raw=frame.replace('<165>',prefix)+suffix;
      expect(rfc5424SdByteEscapes(asBytes(raw))).toBeNull();
    }
    const longApp=frame.replace(' evntslog ', ' '+'a'.repeat(49)+' ')+suffix;
    expect(rfc5424SdByteEscapes(asBytes(longApp))).toBeNull();
  });
  it('treats spaced bracket after an SD element as MSG, not another SD element',()=>{
    const text=frame+'[example@32473 a="v"] [other@32473 b="next"]';
    const result=rfc5424SdByteEscapes(asBytes(text))!;
    expect(result.elements).toHaveLength(1);
    expect(slice(text,result.messageStart!,asBytes(text).length))
      .toBe('[other@32473 b="next"]');
  });
});
