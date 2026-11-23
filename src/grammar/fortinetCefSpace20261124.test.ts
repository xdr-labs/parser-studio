import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {detectStructuredFamily,extractStructuredFamily} from '../structuredFamilies';
import {structuredFamilyClaim} from '../genericStructural';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from '../guided/autoParserEnvelope';
import {prepareAutoParserDraft} from '../guided/autoParserDraft';
import type {BackendCapabilities} from '../guided/backendCapabilities';

// Golden fortinet_cef (PUBLISHER_ORIGINAL, Fortinet FortiOS 6.4.4 Log Message Reference): FortiGate writes its CEF
// output as "CEF: 0|" - one space after the colon. It was read as space_kv text, deviceExternalId hidden in a
// larger value, and still reported FULL (2 false FULL events, 2 lost values).
const FGT='Dec 27 11:07:55 FGT-A-LOG CEF: 0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward src=10.1.100.11 spt=54190 dst=52.53.140.235 dpt=443 proto=6 act=close';
const FGT2=FGT.replace('11:07:55','11:12:30').replace('close|3|','accept|3|').replace('spt=54190','spt=58843')
  .replace('dst=52.53.140.235 dpt=443 proto=6 act=close','dst=172.16.200.55 dpt=53 proto=17 act=accept');
const BODY=FGT.slice(FGT.indexOf('CEF:'));
const cap={authoring:{extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;

describe('CEF with one space after the colon (FortiGate form)',()=>{
  it('reads the version, the six header fields and the extension',()=>{
    expect(detectStructuredFamily(BODY)).toBe('cef');
    expect(structuredFamilyClaim(BODY)).toBe('CEF');
    const read=extractStructuredFamily(BODY,'cef');
    expect(read.errors).toEqual([]);
    expect(read.fields).toMatchObject({cef_version:'0',cef_device_vendor:'Fortinet',cef_device_product:'Fortigate',
      cef_device_version:'v6.0.3',cef_signature_id:'00013',cef_name:'traffic:forward close',cef_severity:'3',
      deviceExternalId:'FGT5HD3915800610',cat:'traffic:forward',src:'10.1.100.11',spt:'54190',act:'close'});
    // The same record without the space reads the same.
    expect(extractStructuredFamily(BODY.replace('CEF: 0|','CEF:0|'),'cef').fields).toEqual(read.fields);
  });
  it.each([
    ['two spaces','CEF:  0|Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1'],
    ['a tab','CEF:\t0|Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1'],
    ['a space before the colon','CEF :0|Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1'],
    ['a space after the version','CEF: 0 |Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1'],
    ['no version','CEF: |Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1'],
    ['a word','CEF: zero|Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1'],
    ['too few header fields','CEF: 0|Fortinet|Fortigate|v6.0.3|00013|n'],
  ])('does not read %s as CEF',(_,line)=>{
    expect(extractStructuredFamily(line,'cef').errors.length).toBeGreaterThan(0);
  });
  it('maps and keeps every value of the golden FortiGate lines (Auto Parser journey), each event FULL',()=>{
    const source=[FGT,FGT2].join('\n');
    const draft=createDraft();
    const ledger=analyzeLogEnvelopes(source,'single-line');
    const ready=prepareAutoParserDraft(source,draft,preview(source,draft),ledger,assessEnvelopeCompilation(ledger,cap));
    if(!ready.ok)throw new Error(ready.reason);
    const events=preview(source,ready.draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    expect(events.map(event=>[event.normalized.srcip,event.normalized.dstip,event.normalized.srcport,event.normalized.dstport]))
      .toEqual([['10.1.100.11','52.53.140.235',54190,443],['10.1.100.11','172.16.200.55',58843,53]]);
    for(const [index,event] of events.entries()){
      const text=JSON.stringify(event.normalized);
      for(const value of ['FGT5HD3915800610','traffic:forward',index?'accept':'close'])expect(text).toContain(JSON.stringify(value));
    }
  });
});
