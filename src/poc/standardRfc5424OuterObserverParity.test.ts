import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {inspectGeneralSyslogEnvelope} from './generalSyslogEnvelopeSpans';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {arbitrateSourceBody} from './boundedSourceBodyArbiter';

type SourceField={name:string;value:string;startByte:number;endByte:number};
type Case={id:string;wire:string;valid:boolean;expected:SourceField[];
 sourceBytes:number;sourceSha256:string;sdStartByte?:number;
 sdEndByte?:number;messageStartByte?:number;
 originAttribution:'UNSCORABLE';outerHeaderProvenance?:string};
const fixture=fs.readFileSync(path.join(__dirname,
 '../../scripts/poc/standardRfc5424OuterObserverParity.pinned.json'));
const SHA='acc3e484221c9edb48c3952d3c4b7e023c4ecae86433974f80110ea900dee4db';
if(createHash('sha256').update(fixture).digest('hex')!==SHA)
 throw Error('Independent original RFC5424 source answer changed');
const {cases}=JSON.parse(fixture.toString('utf8')) as {cases:Case[]};
const decoder=new TextDecoder('utf8',{fatal:true});

describe('P0-STD RFC5424 outer general observer and SD byte/browser grammar parity',()=>{
 it('freezes synthetic source-and-offset answer denominators',()=>{
   expect(cases).toHaveLength(14);
   expect(cases.filter(c=>c.valid)).toHaveLength(8);
   expect(cases.filter(c=>!c.valid)).toHaveLength(6);
 });
 it.each(cases)('does not override RFC5424 mandated SD or invent relay provenance: $id',test=>{
   const wireBytes=new TextEncoder().encode(test.wire);
   expect(wireBytes).toHaveLength(test.sourceBytes);
   expect(createHash('sha256').update(wireBytes).digest('hex')).toBe(test.sourceSha256);
   const general=inspectGeneralSyslogEnvelope(test.wire);
   const reference=rfc5424SdByteEscapes(wireBytes);
   const browser=parseRfc5424Subset(test.wire);
   expect(general.originalRaw).toBe(test.wire);
   expect(general.sourceBytes).toBe(test.sourceBytes);
   expect(general.autoPromoted).toBe(false);
   expect(general.nativeParser).toBe('NOT_VERIFIED');
   expect(general.manufacturerSemantics).toBe('NOT_CERTIFIED');
   expect(general.disposition==='REVIEW_ONLY').toBe(test.valid);
   expect(reference!==null).toBe(test.valid);
   expect(browser.ok).toBe(test.valid);
   if(!test.valid){
     expect(general.fields).toEqual([]);
     return;
   }
   expect(general.format).toBe('rfc5424');
   const sourceArbitration=arbitrateSourceBody(test.wire);
   if(test.id==='SD-REPEATED-SAME-PARAM'){
     expect(general.repeatedSdParamNames).toBe(1);
     expect(sourceArbitration).toMatchObject({
       disposition:'ABSTAIN_UNSAFE',
       raw:test.wire,
       envelopeMode:'rfc5424',
       bodyClaims:[],
       autoPromoted:false,
       nativeVerified:false,
       reason:'RFC5424_REPEATED_SD_PARAM_PRODUCER_SEMANTICS_UNVERIFIED',
     });
   }else {
     expect(general.repeatedSdParamNames).toBeUndefined();
     expect(sourceArbitration.autoPromoted).toBe(false);
     expect(sourceArbitration.nativeVerified).toBe(false);
   }
   expect(general.fields).toEqual(test.expected.map(c=>({
     name:c.name,value:c.value,type:'string',
     startByte:c.startByte,endByte:c.endByte,
   })));
   for(const field of test.expected)
     expect(decoder.decode(wireBytes.subarray(field.startByte,field.endByte)))
       .toBe(field.value);
   expect(reference?.structuredDataStart).toBe(test.sdStartByte);
   expect(reference?.structuredDataEnd).toBe(test.sdEndByte);
   expect(reference?.messageStart).toBe(test.messageStartByte);
   expect(reference?.nativeTarget).toBe('NOT_VERIFIED');
   expect(reference?.canAutoPromote).toBe(false);
   // The source lexical outer relay hostname is not an authoritative
   // original-device identity. A nested Syslog message is not promoted.
   expect(test.originAttribution).toBe('UNSCORABLE');
   expect(general.fields.filter(x=>x.name==='hostname')).toHaveLength(1);
   expect(browser.ok&&browser.fields.syslog_hostname).toBe('edge-relay');
 });
});
