import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {priOnlyPrefix} from '../structuredFamilies';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from '../guided/autoParserEnvelope';
import {prepareAutoParserDraft} from '../guided/autoParserDraft';
import type {BackendCapabilities} from '../guided/backendCapabilities';

// A bare PRI before a CEF or LEEF event (`<189>CEF:0|...`, FortiGate `<189>CEF: 0|...`), read by a bounded path:
// the PRI of the shared contract (value 0..191), optional blanks, then an event the CEF/LEEF grammar reads. It is not
// an RFC 3164 record and the RFC 3164 reader does not take it. The Python Multi-Pass preview reads the same lines
// (tests/test_pri_only_cef_20261125.py) and the generated Ruby runs this reader (extractEvent, translated).
// SYNTHETIC lines shaped like the FortiGate CEF golden case and the IBM QRadar LEEF guide example.
const cap={authoring:{extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
function journey(lines:readonly string[]){
  const source=lines.join('\n');
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(source,'single-line');
  return prepareAutoParserDraft(source,draft,preview(source,draft),ledger,assessEnvelopeCompilation(ledger,cap));
}
const CEF='CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|src=10.1.100.11 spt=54190 dst=52.53.140.235 dpt=443 act=close msg=a\\=b c\\\\d';
const CEF2=CEF.replace('spt=54190','spt=58843').replace('10.1.100.11','10.1.100.12');
const LEEF='LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=192.0.2.10^dst=172.50.123.1^sev=5^usrName=joe.black';
const LEEF2=LEEF.replace('192.0.2.10','192.0.2.11').replace('joe.black','ann.lee');

describe('a bare PRI before a valid CEF or LEEF event',()=>{
  it.each([
    ['<189>CEF:0|',['<189>'+CEF,'<189>'+CEF2],'cef'],
    ['FortiGate <189>CEF: 0|',['<189>'+CEF.replace('CEF:0|','CEF: 0|'),'<189>'+CEF2.replace('CEF:0|','CEF: 0|')],'cef'],
    ['PRI 0 and PRI 191',['<0>'+CEF,'<191>'+CEF2],'cef'],
    ['a blank after the PRI (as the Python reader)',['<189> '+CEF,'<189>\t'+CEF2],'cef'],
    ['PRI and no PRI in one sample',['<189>'+CEF,CEF2],'cef'],
    ['<111>LEEF:2.0|',['<111>'+LEEF,'<111>'+LEEF2],'leef'],
  ])('%s: FULL, PRI read, every value kept',(_,lines,format)=>{
    const ready=journey(lines);
    if(!ready.ok)throw new Error(ready.reason);
    expect(ready.draft.format).toBe(format);
    const events=preview(lines.join('\n'),ready.draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    for(const [index,event] of events.entries()){
      const line=lines[index]!;
      const pri=/^<(\d+)>/.exec(line);
      if(pri)expect(event.fields.syslog_pri).toBe(Number(pri[1]));
      else expect(event.fields.syslog_pri).toBeUndefined();
      const record=(pri?event.fields.body:event.fields) as Record<string,unknown>;
      if(format==='cef'){
        expect([record.cef_device_vendor,record.cef_severity,record.src,record.dpt,record.msg]).toEqual(
          ['Fortinet','3',line.includes('10.1.100.11')?'10.1.100.11':'10.1.100.12','443','a=b c\\d']);
      }else expect([record.leef_vendor,record.src,record.usrName]).toEqual(
        ['Lancope',line.includes('192.0.2.10')?'192.0.2.10':'192.0.2.11',line.includes('joe.black')?'joe.black':'ann.lee']);
    }
  });
});

describe('what the bounded path refuses',()=>{
  it.each([
    ['PRI above 191','<192>'+CEF],
    ['four-digit PRI','<1890>'+CEF],
    ['empty PRI','<>'+CEF],
    ['CEF version 1','<189>'+CEF.replace('CEF:0|','CEF:1|')],
    ['incomplete CEF header','<189>CEF:0|A|B|1|2|n|src=1.1.1.1'],
    ['a space before the colon','<189>'+CEF.replace('CEF:0|','CEF :0|')],
    ['two spaces after the colon','<189>'+CEF.replace('CEF:0|','CEF:  0|')],
    ['free text after a PRI','<189>CEF : 3 alerts today'],
    ['prose after a PRI','<189>hello world'],
    ['LEEF with a space after the colon','<111>'+LEEF.replace('LEEF:','LEEF: ')],
  ])('%s is never read as CEF/LEEF',(_,line)=>{
    expect(journey([line,line]).ok).toBe(false);
    for(const format of ['cef','leef'] as const){
      const event=preview(line,{...createDraft(),format})!.events[0]!;
      expect(event.parseStatus).not.toBe('FULL');
    }
  });
  it('an extension cannot overwrite the PRI and a LEEF event is not read by a CEF parser',()=>{
    const cef=preview('<189>'+CEF+' syslog_pri=7',{...createDraft(),format:'cef'}).events[0]!;
    expect([cef.parseStatus,cef.fields.syslog_pri,(cef.fields.body as Record<string,unknown>).syslog_pri]).toEqual(['FULL',189,'7']);
    expect(preview('<111>'+LEEF,{...createDraft(),format:'cef'}).events[0]!.parseStatus).not.toBe('FULL');
  });
  it('the prefix rule itself',()=>{
    expect(priOnlyPrefix('<189>CEF:0|a')).toEqual({pri:189,end:5,family:'cef'});
    expect(priOnlyPrefix('<7>  LEEF:1.0|a')).toEqual({pri:7,end:5,family:'leef'});
    expect(priOnlyPrefix('<192>CEF:0|a')).toBeNull();
    expect(priOnlyPrefix('<189>Dec 27 11:07:55 host CEF:0|a')).toBeNull();
    expect(priOnlyPrefix('CEF:0|a')).toBeNull();
  });
});

describe('existing CEF forms are unchanged',()=>{
  it.each([
    ['CEF:0|',[CEF,CEF2],'cef'],
    ['CEF: 0|',[CEF.replace('CEF:0|','CEF: 0|'),CEF2.replace('CEF:0|','CEF: 0|')],'cef'],
    ['RFC 3164 + CEF',['<189>Dec 27 11:07:55 FGT-A-LOG '+CEF,'<189>Dec 27 11:07:56 FGT-A-LOG '+CEF2],'syslog_rfc3164'],
    ['RFC 5424 + CEF',['<189>1 2026-11-24T00:00:00Z FGT-A-LOG app - - - '+CEF,'<189>1 2026-11-24T00:00:01Z FGT-A-LOG app - - - '+CEF2],'syslog_rfc5424'],
  ])('%s',(_,lines,format)=>{
    const ready=journey(lines);
    if(!ready.ok)throw new Error(ready.reason);
    expect(ready.draft.format).toBe(format);
    expect(preview(lines.join('\n'),ready.draft).events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
  });
});
