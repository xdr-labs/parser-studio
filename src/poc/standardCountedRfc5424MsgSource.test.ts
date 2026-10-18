import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {splitSyslogStream} from '../syslogFraming';
import {parseSyslogEnvelope} from '../syslogEnvelope';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {inspectCountedRfc5424MsgStream} from './standardCountedRfc5424MsgSource';

type Claim={
  record:string;recordStartByte:number;recordEndByte:number;
  msg:string|null;msgStartByte:number|null;msgEndByte:number|null;
};
type Case={
  id:string;wire:string;valid:boolean;sha256:string;
  streamBytes:number;claims:Claim[];
};
const frozen=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardCountedRfc5424MsgSource.pinned.json'));
const digest='c43c7b0f604777f12ce5491206ec0295e3975310e44f1042c6b373fb27011852';
const sha=(raw:Uint8Array)=>createHash('sha256').update(raw).digest('hex');
if(sha(frozen)!==digest)throw Error('RFC6587/RFC5424 authored source truth SHA drift');
const cases=(JSON.parse(frozen.toString('utf8')) as {cases:Case[]}).cases;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});

describe('P0-STD RFC6587 counted context and RFC5424 original MSG byte source',()=>{
  it('freezes all standalone standards-derived cases before candidate scoring',()=>{
    expect(cases).toHaveLength(22);
    expect(cases.filter(x=>x.valid)).toHaveLength(11);
    expect(cases.filter(x=>!x.valid)).toHaveLength(11);
    expect(cases.flatMap(x=>x.claims)).toHaveLength(13);
  });
  it.each(cases.filter(x=>x.valid))('accepts only counted-source RFC5424 MSG: $id',t=>{
    const original=encoder.encode(t.wire);
    expect(sha(original)).toBe(t.sha256);
    expect(original).toHaveLength(t.streamBytes);
    const stream=splitSyslogStream(t.wire);
    expect(stream.ok).toBe(true);
    if(!stream.ok)return;
    expect(stream.mode).toBe('rfc6587_octet_counting_stream');
    expect(stream.records).toEqual(t.claims.map(c=>c.record));
    const recordBytes=stream.records.map(s=>encoder.encode(s));
    for(const [i,claim] of t.claims.entries()){
      expect(decoder.decode(original.subarray(claim.recordStartByte,claim.recordEndByte)))
        .toBe(claim.record);
      expect(recordBytes[i]!.length).toBe(claim.recordEndByte-claim.recordStartByte);
      const browser=parseRfc5424Subset(claim.record,
        {framing:'RFC6587_OCTET_COUNTING'});
      const source=parseSyslogEnvelope(claim.record,
        {framing:'RFC6587_OCTET_COUNTING'});
      expect(browser.ok,t.id).toBe(true);
      expect(source?.variant,t.id).toBe('rfc5424');
      if(browser.ok)expect(browser.message).toBe(claim.msg);
      expect(source?.message).toBe(claim.msg??'');
      if(claim.msg!==null){
        expect(claim.msgStartByte).not.toBeNull();
        expect(claim.msgEndByte).not.toBeNull();
        expect(decoder.decode(original.subarray(
          claim.msgStartByte!,claim.msgEndByte!))).toBe(claim.msg);
      }else {
        expect(claim.msgStartByte).toBeNull();
        expect(claim.msgEndByte).toBeNull();
      }
      if(/[\r\n\0]/.test(claim.record)){
        expect(parseRfc5424Subset(claim.record).ok).toBe(false);
        expect(parseSyslogEnvelope(claim.record)).toBeNull();
      }
    }
  });
  it.each(cases.filter(x=>!x.valid))('rejects unproven counted-source MSG: $id',t=>{
    const bytes=encoder.encode(t.wire);
    expect(sha(bytes)).toBe(t.sha256);
    expect(bytes).toHaveLength(t.streamBytes);
    const split=splitSyslogStream(t.wire);
    if(!split.ok)return;
    if(split.mode!=='rfc6587_octet_counting_stream')return;
    expect(split.records.some(record=>{
      const browser=parseRfc5424Subset(record,{framing:'RFC6587_OCTET_COUNTING'});
      const source=parseSyslogEnvelope(record,{framing:'RFC6587_OCTET_COUNTING'});
      return !browser.ok || source?.variant!=='rfc5424';
    })).toBe(true);
  });
  it.each(cases)('scores exact original wire intervals without native claims: $id',c=>{
    const result=inspectCountedRfc5424MsgStream(c.wire);
    expect(result.sourceBytes).toBe(c.streamBytes);
    expect(result.raw).toBe(c.wire);
    expect(result.canAutoPromote).toBe(false);
    expect(result.sourceComplete).toBe(false);
    expect(result.nativeVerified).toBe(false);
    expect(result.manufacturerVerified).toBe(false);
    if(!c.valid){
      expect(result.disposition).toBe('ABSTAIN_UNSAFE');
      expect(result.claims).toHaveLength(0);
      return;
    }
    expect(result.disposition).toBe('REVIEW_ONLY_COUNTED_MSG_SOURCE');
    expect(result.claims).toHaveLength(c.claims.length);
    const wire=encoder.encode(c.wire);
    for(const [i,expected] of c.claims.entries()){
      const claim=result.claims[i]!;
      expect({
        record:claim.recordRaw,recordStartByte:claim.recordStartByte,
        recordEndByte:claim.recordEndByte,msg:claim.msg,
        msgStartByte:claim.msgStartByte,msgEndByte:claim.msgEndByte,
      }).toEqual(expected);
      if(expected.msg!==null){
        expect(decoder.decode(wire.subarray(claim.msgStartByte!,claim.msgEndByte!)))
          .toBe(expected.msg);
        expect(claim.messageEncoding).toBe(expected.msg.startsWith('\ufeff')?
          'MSG_UTF8_BOM':'MSG_ANY');
      }else expect(claim.messageEncoding).toBe('NO_MSG');
    }
  });
  it('abstains before UTF-8 replacement of a lone UTF-16 surrogate',()=>{
    const invalid='<134>1 2026-10-18T12:00:00Z fw01 security 90 EVT - msg\uD800';
    const framed=encoder.encode(invalid).length+' '+invalid;
    expect(splitSyslogStream(framed).ok).toBe(false);
  });
});
