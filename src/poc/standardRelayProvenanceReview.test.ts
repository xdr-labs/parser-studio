import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,it,expect} from 'vitest';
import {reviewNestedSyslogProvenance} from './standardRelayProvenanceReview';

type Case={
  id:string;receiverRaw:string;receiverSha256:string;
  upstreamRaw:string|null;upstreamSha256:string|null;
  expected:string;expectedOuterHost:string|null;
  expectedInnerHost:string|null;expectedInnerByteStart:number|null;expectedInnerRaw:string|null;
};
const frozen=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardRelayProvenanceReview.pinned.json'));
const pinnedSha='d22ba4469494deb3394ececb09a075acc8043cbbac7c843681614bb7b064253a';
const sha=(bytes:Uint8Array)=>
  createHash('sha256').update(bytes).digest('hex');
if(sha(frozen)!==pinnedSha)throw Error('Independent syslog relay provenance oracle SHA changed');
const cases=(JSON.parse(frozen.toString('utf8')) as {cases:Case[]}).cases;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});

describe('P0-STD RFC5424/RFC5425 source-vs-relay observable-only provenance',()=>{
  it('freezes original standards-derived transport/host/time expectations first',()=>{
    expect(cases).toHaveLength(17);
    expect(cases.filter(x=>x.expected==='REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH'))
      .toHaveLength(6);
    expect(cases.filter(x=>x.expected==='ABSTAIN_UNSAFE_SOURCE')).toHaveLength(6);
  });
  it.each(cases)('does not authenticate producer identity from $id',c=>{
    const received=encoder.encode(c.receiverRaw);
    expect(sha(received)).toBe(c.receiverSha256);
    const upstream=c.upstreamRaw===null?undefined:encoder.encode(c.upstreamRaw);
    if(upstream)expect(sha(upstream)).toBe(c.upstreamSha256);
    const result=reviewNestedSyslogProvenance(received,upstream);
    expect(result.disposition).toBe(c.expected);
    expect(result.receiverBytes).toBe(received.length);
    expect(result.outer?.hostname??null).toBe(c.expectedOuterHost);
    expect(result.inner?.hostname??null).toBe(c.expectedInnerHost);
    if(c.expectedInnerByteStart!==null){
      expect(result.innerSource?.startByte).toBe(c.expectedInnerByteStart);
      const source=result.innerSource!;
      expect(source.endByte).toBe(received.length);
      expect(decoder.decode(received.subarray(source.startByte,source.endByte)))
        .toBe(c.expectedInnerRaw);
    }
    expect(result.transportPeerAuthentication).toBe('NOT_VERIFIED');
    expect(result.originalDeviceIdentity).toBe('NOT_ATTESTED');
    expect(result.eventClockOrdering).toBe('UNSCORABLE');
    expect(result.sourceComplete).toBe(false);
    expect(result.nativeVerified).toBe(false);
    expect(result.canAutoPromote).toBe(false);
  });
  it('refuses non-UTF-8 and source bounds even if caller claims a paired original',()=>{
    const raw=encoder.encode(cases[0]!.receiverRaw);
    const upstream=encoder.encode(cases[0]!.upstreamRaw!);
    const altered=new Uint8Array(raw);
    altered[altered.length-1]=0xff;
    const unsafe=[
      altered,new Uint8Array([0xef,0xbb,0xbf,...raw]),
      encoder.encode(cases[0]!.receiverRaw+' '.repeat(8192)),
      encoder.encode(cases[0]!.receiverRaw+'\r\n'),
    ];
    for(const sample of unsafe){
      const result=reviewNestedSyslogProvenance(sample,upstream);
      expect(result.disposition).toBe('ABSTAIN_UNSAFE_SOURCE');
      expect(result.canAutoPromote).toBe(false);
      expect(result.innerSource).toBeNull();
    }
  });
  it('does not treat a forged authenticated peer label as TLS evidence',()=>{
    const c=cases[0]!;
    const result=reviewNestedSyslogProvenance(
      encoder.encode(c.receiverRaw),encoder.encode(c.upstreamRaw!));
    expect(result.disposition).toBe('REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH');
    expect(result.originalDeviceIdentity).toBe('NOT_ATTESTED');
    expect(result.transportPeerAuthentication).toBe('NOT_VERIFIED');
  });
});
