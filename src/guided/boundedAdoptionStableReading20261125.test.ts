/**
 * Adoption of the bounded compiler's reading: keeping the text of an event is not parsing it (owner decision of
 * 2026-11-25; independent audit of e8d8d26, C-1 and C-2).
 *
 * `evt=flow_open fragmented client=... server=... verdict=permit` behind a Syslog header was adopted with a reading
 * that keeps the whole body as one message: the sample was reported as structurally parsed although no pair was
 * extracted, and no ChatGPT route was offered. An event with one more pair was then read in another shape (space
 * separated key=value, the header as positional pieces), so the fields of the parser changed their paths.
 *
 * A reading is adopted only when (1) it does not hold key=value pairs as message text and (2) the same event with
 * one more key=value pair at its end is read the same way: same reading mode, every value under its name. An event
 * that is not adopted stays with the first scan, which asks for a rule (ChatGPT Assisted). SYNTHETIC lines.
 */
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {buildSourceReviewedBoundedDraft,headerlessCsvEvents,nativelyReadEvents,
  type GenericStructuralSourceReview} from './genericStructuralAutoDraft';

function parsedWitness(source:string):GenericStructuralSourceReview{
  const encoder=new TextEncoder();let offset=0;
  const events=source.split('\n').map(line=>{
    const startByte=offset,endByte=offset+encoder.encode(line).byteLength;
    offset=endByte+1;
    return {startByte,endByte,preview:{status:'SOURCE_PARSED' as const,issues:[]}};
  });
  return {raw:source,events};
}
function adopt(lines:readonly string[]){
  const source=lines.join('\n');
  const report=analyzeLogEnvelopes(source,'single-line');
  return buildSourceReviewedBoundedDraft(source,createDraft(),parsedWitness(source),
    headerlessCsvEvents(report.events),nativelyReadEvents(report.events));
}
const modes=(lines:readonly string[])=>adopt(lines)?.suite.events.map(event=>(event.fields.generic as {mode:string}).mode)??null;
const H=(n:number)=>'<134>Nov 25 09:10:0'+n+' gw-norrland quillfw: ';

describe('a reading that keeps key=value pairs as message text is not adopted',()=>{
  it('four pairs and a bare token: one more pair would be read in another shape',()=>{
    expect(adopt([H(1)+'evt=flow_open fragmented client=10.44.7.21 server=198.51.100.77 verdict=permit',
      H(2)+'evt=flow_close reassembled client=10.44.7.22 server=198.51.100.78 verdict=deny'])).toBeNull();
  });
  it('two pairs and a bare token: the reading is stable, but the pairs are only text',()=>{
    expect(adopt([H(1)+'evt=flow_open fragmented client=10.44.7.21',H(2)+'evt=flow_close reassembled client=10.44.7.22'])).toBeNull();
  });
  it.each(['op=sess_new;initiator=10.72.5.31;responder=192.0.2.141 trusted',
    'op="sess_new",initiator="10.72.5.31",responder="192.0.2.141" trusted'])(
    'pairs separated by ; or , with a bare token (final audit F-2): %s',body=>{
    expect(adopt([H(1)+body,H(2)+body.replace('5.31','5.32')])).toBeNull();
  });
  it('one such event beside a free-text event is enough',()=>{
    expect(adopt([H(1)+'service restarted',H(2)+'evt=flow_close reassembled client=10.44.7.22 server=198.51.100.78 verdict=deny'])).toBeNull();
  });
});

describe('readings that are adopted as before',()=>{
  it('free text behind a Syslog header, kept whole as message',()=>{
    expect(modes([H(1)+'service restarted',H(2)+'service stopped'])).toEqual(['bsd_tagged_message','bsd_tagged_message']);
    expect(modes(['Nov 25 09:10:08 bastion sudo: pam_unix(sudo:session): session opened for user root by ops(uid=1001)',
      'Nov 25 09:10:09 bastion sudo: pam_unix(sudo:session): session closed for user root'])).toEqual(['bsd_tagged_message','bsd_tagged_message']);
  });
  it('prose with a single key=value token',()=>{
    expect(modes([H(1)+'session closed for uid=1001',H(2)+'session opened for uid=1002'])).toEqual(['bsd_tagged_message','bsd_tagged_message']);
  });
  it('space separated key=value with a bare token, read as pairs',()=>{
    expect(modes([H(1)+'evt=flow_open fragmented client=10.44.7.21 server=198.51.100.77 verdict=permit zone=dmz',
      H(2)+'evt=flow_close reassembled client=10.44.7.22 server=198.51.100.78 verdict=deny zone=lan'])).toEqual(['space_kv','space_kv']);
  });
  // A text prefix followed by two to four pairs behind a BSD Syslog header is the reading of the selected profile
  // syslog_prefix_kv; with five pairs or more the same line is the older space separated reading. Both extract the
  // pairs under generic.kv.*, so the boundary between them is not a reason to refuse the event (regression of
  // 1e909af found by the CI step that runs tests/*.isolated.ts: the profile was never adopted any more).
  it('a text prefix followed by key=value pairs behind a Syslog header, read as pairs',()=>{
    const ftd='<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected signature=1000123 src=192.0.2.40 dst=198.51.100.5 action=block';
    const adopted=adopt([ftd]);
    expect(adopted?.suite.events.map(event=>(event.fields.generic as {mode:string}).mode)).toEqual(['syslog_prefix_kv']);
    expect((adopted!.suite.events[0]!.fields.generic as {kv:Record<string,string>}).kv)
      .toEqual({signature:'1000123',src:'192.0.2.40',dst:'198.51.100.5',action:'block'});
    expect(modes(['<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected signature=1000123 src=192.0.2.40',
      '<134>Oct 19 08:24:00 ftd01 %FTD-4-430002: Intrusion event detected signature=1000124 src=192.0.2.41']))
      .toEqual(['syslog_prefix_kv','syslog_prefix_kv']);
  });
  it('positional pieces before the pairs',()=>{
    expect(modes(['2026-11-25 10:00:00 fw1 allow srcip=10.0.0.1 dstip=10.0.0.2 srcport=1 dstport=2 proto=6',
      '2026-11-25 10:00:01 fw1 deny srcip=10.0.0.3 dstip=10.0.0.4 srcport=3 dstport=4 proto=17'])).toEqual(['space_kv','space_kv']);
  });
});
