import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {inspectGeneralSyslogEnvelope} from './generalSyslogEnvelopeSpans';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';
import {arbitrateSourceBody} from './boundedSourceBodyArbiter';

type Field={name:string;value:string;startByte:number;endByte:number};
type Case={id:string;wire:string;validVersion1:boolean;wireSha256:string;
 sourceBytes:number;fields:Field[];sdStartByte?:number;sdEndByte?:number;
 messageStartByte?:number;notNative:boolean;notDeviceOriginProven:boolean};
const source=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardRfc5424TimeVersion.pinned.json'));
const sha='2a281fccd420261d1387569a1d73ef7a8984b9ab33fb2ff711f0bac6eba0eced';
if(createHash('sha256').update(source).digest('hex')!==sha)
  throw Error('Source-independent RFC5424 TIMESTAMP/VERSION oracle changed');
const {cases}=JSON.parse(source.toString('utf8')) as {cases:Case[]};
const decoder=new TextDecoder('utf8',{fatal:true});

describe('P0-STD RFC5424 v1 TIME-SECFRAC and version guard',()=>{
 it('pins the independent standard-derived syntax truth before parser scoring',()=>{
  expect(cases).toHaveLength(14);
  expect(cases.filter(c=>c.validVersion1)).toHaveLength(6);
  expect(cases.filter(c=>!c.validVersion1)).toHaveLength(8);
 });
 it.each(cases)('accepts only independently reviewed RFC5424 version/time source: $id',c=>{
  const bytes=new TextEncoder().encode(c.wire);
  expect(bytes).toHaveLength(c.sourceBytes);
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(c.wireSha256);
  const general=inspectGeneralSyslogEnvelope(c.wire);
  const browser=parseRfc5424Subset(c.wire);
  const sourceByte=rfc5424SdByteEscapes(bytes);
  expect(general.sourceBytes).toBe(c.sourceBytes);
  expect(general.originalRaw).toBe(c.wire);
  expect(general.autoPromoted).toBe(false);
  expect(general.nativeParser).toBe('NOT_VERIFIED');
  expect(general.manufacturerSemantics).toBe('NOT_CERTIFIED');
  expect(general.disposition==='REVIEW_ONLY').toBe(c.validVersion1);
  expect(browser.ok).toBe(c.validVersion1);
  expect(sourceByte!==null).toBe(c.validVersion1);
  if(!c.validVersion1){
   expect(general.fields).toEqual([]);
   const arb=arbitrateSourceBody(c.wire);
   expect(arb.disposition).toBe('ABSTAIN_UNSAFE');
   expect(arb.autoPromoted).toBe(false);
   return;
  }
  expect(general.format).toBe('rfc5424');
  // RFC5424 NILVALUE '-' remains present in the original source, but
  // the source observer deliberately omits missing header identities.
  const observedClaims=c.fields.filter(f=>!(f.name==='timestamp'&&f.value==='-'));
  expect(general.fields).toEqual(observedClaims.map(f=>({
   name:f.name,value:f.value,type:'string',
   startByte:f.startByte,endByte:f.endByte,
  })));
  for(const original of c.fields){
   expect(decoder.decode(bytes.subarray(original.startByte,original.endByte)))
    .toBe(original.value);
  }
  expect(sourceByte?.structuredDataStart).toBe(c.sdStartByte);
  expect(sourceByte?.structuredDataEnd).toBe(c.sdEndByte);
  expect(sourceByte?.messageStart).toBe(c.messageStartByte);
  expect(sourceByte?.canAutoPromote).toBe(false);
  expect(sourceByte?.nativeTarget).toBe('NOT_VERIFIED');
  expect(c.notNative).toBe(true);
  expect(c.notDeviceOriginProven).toBe(true);
 });
});
