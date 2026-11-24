import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {readEvent} from './readEvent';
import {extractionSettingsOf} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from '../guided/autoParserEnvelope';
import {prepareAutoParserDraft} from '../guided/autoParserDraft';
import type {BackendCapabilities} from '../guided/backendCapabilities';

// Owner decision D-2 (2026-11-25): a message that looks like CEF or LEEF but has no valid header is not read as CEF
// or LEEF. The RFC 5424 (or RFC 3164) envelope is read, the message is kept whole as text, and the event is PARTIAL,
// never FULL. The Python Multi-Pass preview reports the same (tests/test_malformed_claim_d2_20261125.py), and the
// generated Ruby runs this reader (readEvent, translated) and hands the PARTIAL event over. SYNTHETIC lines.
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
const H5='<134>1 2026-11-24T10:00:00Z host1 app 123 - - ';
const H3='<134>Nov 24 10:00:00 host1 app: ';

describe('a message that only claims CEF or LEEF',()=>{
  it.each([
    ['RFC 5424, CEF with a count',[H5+'CEF : 3 alerts today',H5+'CEF : 4 alerts today'],'syslog_rfc5424'],
    ['RFC 5424, CEF with a space before the colon',[H5+'CEF :0|A|B|1|2|n|3|x',H5+'CEF :0|A|B|1|2|n|3|y'],'syslog_rfc5424'],
    ['RFC 5424, LEEF without a header',[H5+'LEEF : 2 events',H5+'LEEF : 7 events'],'syslog_rfc5424'],
    ['RFC 5424, claim after a BOM',[H5+'﻿CEF : 3 alerts today',H5+'﻿CEF : 5 alerts today'],'syslog_rfc5424'],
    // The Auto Parser journey does not offer this RFC 3164 tagged-message form (MIXED_OR_UNKNOWN, also for plain
    // text), so the RFC 3164 case uses an explicit RFC 3164 raw-body parser.
    ['RFC 3164, CEF with a count',[H3+'CEF : 3 alerts today',H3+'CEF : 4 alerts today'],'syslog_rfc3164'],
  ])('%s: envelope read, message kept whole, PARTIAL',(_,lines,format)=>{
    let draft:ParserDraft;
    if(format==='syslog_rfc3164')draft={...createDraft(),format:'syslog_rfc3164',syslogBodyFormat:'raw'} as ParserDraft;
    else{
      const ready=journey(lines);
      if(!ready.ok)throw new Error(ready.reason);
      draft=ready.draft;
    }
    expect(draft.format).toBe(format);
    const events=preview(lines.join('\n'),draft).events;
    for(const [index,event] of events.entries()){
      expect(event.parseStatus).toBe('PARTIAL');
      expect(event.diagnostics.map(item=>[item.code,item.severity])).toContainEqual(['BODY_KEPT_AS_TEXT','warning']);
      expect(event.diagnostics.some(item=>item.severity==='error')).toBe(false);
      expect(event.fields.message).toBe(lines[index]!.slice((format==='syslog_rfc5424'?H5:H3).length));
      expect(event.fields.syslog_hostname).toBe('host1');
      expect([undefined,'raw']).toContain(event.bodyKind);
      expect(JSON.stringify(event.fields)).not.toMatch(/cef_header|leef_header|"cef"|"leef"/);
    }
  });
  it('is PARTIAL with an explicit raw body as well, and the reading the Ruby runs hands it over',()=>{
    const draft={...createDraft(),format:'syslog_rfc5424',syslogBodyFormat:'raw'} as ParserDraft;
    const reading=readEvent(H5+'CEF : 3 alerts today',extractionSettingsOf(draft,'syslog_rfc5424'));
    expect([reading.status,reading.textKept,reading.fields.message]).toEqual(['PARTIAL',true,'CEF : 3 alerts today']);
    expect(reading.reasons[0]).toBe('the message claims to be CEF but has no valid CEF header; it is kept as text');
  });
});

describe('messages that make no claim, and valid CEF/LEEF',()=>{
  it.each([
    ['plain message',[H5+'service restarted',H5+'service stopped']],
    ['a word CEF without a colon',[H5+'CEF team meeting at 10:00',H5+'CEF team meeting at 11:00']],
  ])('%s stays FULL',(_,lines)=>{
    const ready=journey(lines);
    if(!ready.ok)throw new Error(ready.reason);
    const events=preview(lines.join('\n'),ready.draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    expect(events.every(event=>!event.diagnostics.some(item=>item.code==='BODY_KEPT_AS_TEXT'))).toBe(true);
  });
  it('an RFC 3164 plain message kept by a raw body stays FULL',()=>{
    const draft={...createDraft(),format:'syslog_rfc3164',syslogBodyFormat:'raw'} as ParserDraft;
    expect(preview(H3+'service restarted\n'+H3+'CEF team meeting',draft).events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
  });
  it('a valid CEF message after RFC 5424 is still read as CEF and FULL',()=>{
    const lines=[H5+'CEF:0|Acme|FW|1.0|100|Blocked|5|src=10.0.0.1 dst=10.0.0.2',H5+'CEF:0|Acme|FW|1.0|100|Blocked|5|src=10.0.0.3 dst=10.0.0.4'];
    const ready=journey(lines);
    if(!ready.ok)throw new Error(ready.reason);
    const events=preview(lines.join('\n'),ready.draft).events;
    expect(events.map(event=>[event.parseStatus,event.bodyKind])).toEqual([['FULL','cef'],['FULL','cef']]);
  });
  it('a valid CEF message kept by an explicit raw body is unchanged (FULL, the whole message)',()=>{
    const draft={...createDraft(),format:'syslog_rfc5424',syslogBodyFormat:'raw'} as ParserDraft;
    const reading=readEvent(H5+'CEF:0|Acme|FW|1.0|100|Blocked|5|src=10.0.0.1',extractionSettingsOf(draft,'syslog_rfc5424'));
    expect([reading.status,reading.textKept]).toEqual(['FULL',false]);
  });
});
