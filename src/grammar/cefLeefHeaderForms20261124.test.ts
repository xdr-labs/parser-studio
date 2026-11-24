import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {detectStructuredFamily} from '../structuredFamilies';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from '../guided/autoParserEnvelope';
import {prepareAutoParserDraft} from '../guided/autoParserDraft';
import type {BackendCapabilities} from '../guided/backendCapabilities';

// CEF and LEEF header forms through the Auto Parser journey (Phase 3 grammar checks, 2026-11-24). SYNTHETIC lines
// shaped like the FortiGate CEF golden case and the IBM QRadar LEEF guide example. The same lines were run in the
// Python Multi-Pass preview and, where the journey builds a parser, in the downloaded Ruby on Ruby 2.4.9
// (docs/verification/20261124-phase3-q31-unmapped-fields-fortinet-cef.md).
const cap={authoring:{extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const CEF='CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|src=10.1.100.11 spt=54190 dst=52.53.140.235 dpt=443 act=close';
const CEF2=CEF.replace('spt=54190','spt=58843').replace('act=close','act=accept').replace('close|3|','accept|3|');
const LEEF='LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=192.0.2.10^dst=172.50.123.1^sev=5^cat=anomaly^srcPort=81^dstPort=21^usrName=joe.black';
const LEEF2=LEEF.replace('srcPort=81','srcPort=82').replace('joe.black','ann.lee');
const colon=(body:string,form:string)=>body.replace(/^(CEF|LEEF):/,'$1'+form);
const both=(make:(body:string)=>string,a:string,b:string)=>[make(a),make(b)] as const;
function journey(lines:readonly string[]){
  const source=lines.join('\n');
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(source,'single-line');
  return prepareAutoParserDraft(source,draft,preview(source,draft),ledger,assessEnvelopeCompilation(ledger,cap));
}

describe('header forms the journey reads, every value kept',()=>{
  it.each([
    ['CEF without a syslog header',both(body=>body,CEF,CEF2),'cef'],
    ['FortiGate CEF (one space after the colon) without a syslog header',both(body=>colon(body,': '),CEF,CEF2),'cef'],
    ['CEF after an RFC 3164 header',both(body=>'<189>Dec 27 11:07:55 FGT-A-LOG '+body,CEF,CEF2),'syslog_rfc3164'],
    ['FortiGate CEF after an RFC 3164 header',both(body=>'<189>Dec 27 11:07:55 FGT-A-LOG '+colon(body,': '),CEF,CEF2),'syslog_rfc3164'],
    ['FortiGate CEF after an RFC 3164 header without PRI',both(body=>'Dec 27 11:07:55 FGT-A-LOG '+colon(body,': '),CEF,CEF2),'syslog_rfc3164'],
    ['LEEF 2.0 without a syslog header',both(body=>body,LEEF,LEEF2),'leef'],
    ['LEEF 2.0 after an RFC 3164 header',both(body=>'<111>Apr 19 10:29:53 3.3.3.3 '+body,LEEF,LEEF2),'syslog_rfc3164'],
  ])('%s',(_,lines,format)=>{
    const ready=journey(lines);
    if(!ready.ok)throw new Error(ready.reason);
    expect(ready.draft.format).toBe(format);
    const events=preview(lines.join('\n'),ready.draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    for(const [index,event] of events.entries()){
      expect([event.normalized.srcip,event.normalized.dstip]).toEqual(lines[index]!.includes('LEEF')?
        ['192.0.2.10','172.50.123.1']:['10.1.100.11','52.53.140.235']);
      const text=JSON.stringify(event.normalized);
      for(const [,value] of lines[index]!.matchAll(/[ ^][A-Za-z]+=([^ ^]+)/g))
        expect(text.includes(JSON.stringify(value))||text.includes(JSON.stringify(Number(value))),value).toBe(true);
    }
  });
});

describe('spacing never turns a malformed header into CEF or LEEF',()=>{
  // IBM QRadar LEEF guide: the header is "LEEF:Version|" with no space after the colon (audit A-6), unlike the
  // FortiGate CEF form above, which FortiOS documents.
  it.each([
    ['CEF with a space before the colon',both(body=>colon(body,' :'),CEF,CEF2)],
    ['CEF with two spaces after the colon',both(body=>colon(body,':  '),CEF,CEF2)],
    ['CEF with a space before the colon after a PRI',both(body=>'<189>'+colon(body,' :'),CEF,CEF2)],
    ['CEF with two spaces after the colon after a PRI',both(body=>'<189>'+colon(body,':  '),CEF,CEF2)],
    ['LEEF with a space after the colon',both(body=>colon(body,': '),LEEF,LEEF2)],
    ['LEEF with a space after the colon after a PRI',both(body=>'<111>'+colon(body,': '),LEEF,LEEF2)],
    ['LEEF with a space after the colon after an RFC 3164 header',both(body=>'<111>Apr 19 10:29:53 3.3.3.3 '+colon(body,': '),LEEF,LEEF2)],
  ])('%s',(_,lines)=>{
    const body=lines[0]!.replace(/^<\d+>(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ )?/,'');
    expect(detectStructuredFamily(body)).toBeNull();
    expect(journey(lines).ok).toBe(false);
  });
});
