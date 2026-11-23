import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

// Golden case r2_trendmicro_cef (final audit corpus, MODIFIED_FROM_PUBLISHER: Trend Micro Deep Security syslog
// formats; the documentation ellipsis of TrendMicroDsPacketData removed). The Manager record carries src only,
// the Agent packet record src, dst, spt, dpt and proto=TCP. dst, spt and dpt are CEF keys whose meaning the CEF
// standard defines, yet a record family without them kept them a review proposal.
const DSM='CEF:0|Trend Micro|Deep Security Manager|<DSM version>|600|User Signed In|3|src=10.52.116.160 suser=admin target=admin msg=User signed in from 2001:db8::5';
const DSA='CEF:0|Trend Micro|Deep Security Agent|<DSA version>|20|Log for TCP Port 80|0|cn1=1 cn1Label=Host ID dvc=hostname act=Log dmac=00:50:56:F5:7F:47 smac=00:0C:29:EB:35:DE TrendMicroDsFrameType=IP src=192.168.126.150 dst=72.14.204.147 out=1019 cs3=DF MF cs3Label=Fragmentation Bits proto=TCP spt=49617 dpt=80 cs2=0x00 ACK PSH cs2Label=TCP Flags cnt=1 TrendMicroDsPacketData=AFB';
const cap={authoring:{extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;

function read(format:string,...events:Record<string,unknown>[]){
  return readBody(format,undefined,...events);
}
/** bodyKind: the grammar the Syslog reader reports for the body of each event. */
function readBody(format:string,bodyKind:string|undefined,...events:Record<string,unknown>[]){
  const suite={events:events.map(fields=>({fields,effectiveFormat:format,bodyKind}))} as unknown as SuiteResult;
  return (source:string)=>suggestNormalizationCandidatesFromSuite(suite,[]).filter(item=>item.source===source)
    .map(item=>[item.target,item.confidence]);
}

describe('a CEF or LEEF extension key the specification defines, in some record families only',()=>{
  it('maps the network tuple of the Trend Micro Agent record (journey path)',()=>{
    const source=[DSM,DSA].join('\n');
    const draft=createDraft();
    const ledger=analyzeLogEnvelopes(source,'single-line');
    const ready=prepareAutoParserDraft(source,draft,preview(source,draft),ledger,assessEnvelopeCompilation(ledger,cap));
    if(!ready.ok)throw new Error(ready.reason);
    const [manager,agent]=preview(source,ready.draft).events.map(event=>event.normalized);
    expect(manager).toMatchObject({srcip:'10.52.116.160'});
    expect(manager!.dstip).toBeUndefined();
    expect(agent).toMatchObject({srcip:'192.168.126.150',dstip:'72.14.204.147',srcport:49617,dstport:80,proto_name:'TCP'});
  });

  it('is approved for CEF and LEEF records, in the root or a Syslog body',()=>{
    const cef={cef_version:'0',src:'192.0.2.1',dst:'198.51.100.2',spt:'40000',dpt:'443',proto:'TCP'};
    const leef={leef_version:'2.0',src:'192.0.2.1',dst:'198.51.100.2',srcPort:'40000',dstPort:'443',proto:'6'};
    const other={cef_version:'0',suser:'admin'};
    expect(read('cef',cef,other)('dst')).toEqual([['dstip','HIGH']]);
    expect(read('cef',cef,other)('spt')).toEqual([['srcport','HIGH']]);
    expect(read('cef',cef,other)('proto')).toEqual([['proto_name','HIGH']]);
    expect(read('leef',leef,{leef_version:'2.0',usrName:'admin'})('dstPort')).toEqual([['dstport','HIGH']]);
    expect(read('leef',leef,{leef_version:'2.0',usrName:'admin'})('proto')).toEqual([['proto','HIGH']]);
    expect(readBody('syslog_rfc5424','cef',{body:cef},{body:other})('body.dpt')).toEqual([['dstport','HIGH']]);
  });

  it('stays a review proposal outside a CEF or LEEF reading, or when the value or protocol does not fit',()=>{
    const cef={cef_version:'0',src:'192.0.2.1',dst:'198.51.100.2',spt:'40000',dpt:'443',proto:'TCP'};
    // The same names in a key=value or JSON log are the author's own (the full-coverage rule applies).
    expect(read('kv',{...cef},{cef_version:'0',suser:'admin'})('dst')).toEqual([['dstip','REVIEW']]);
    expect(read('json',{...cef},{cef_version:'0',suser:'admin'})('dst')).toEqual([['dstip','REVIEW']]);
    // Independent audit 2026-11-23 (F2): a JSON or key=value Syslog body that names a key cef_version is not CEF.
    expect(readBody('syslog_rfc5424','json',{body:cef},{body:{cef_version:'0',suser:'admin'}})('body.dst'))
      .toEqual([['dstip','REVIEW']]);
    expect(readBody('syslog_rfc5424','kv',{body:cef},{body:{cef_version:'0',suser:'admin'}})('body.dst'))
      .toEqual([['dstip','REVIEW']]);
    expect(read('syslog_rfc5424',{body:cef},{body:{cef_version:'0',suser:'admin'}})('body.dst'))
      .toEqual([['dstip','REVIEW']]);
    // A CEF record without the version the reader writes is not known to be CEF.
    const {cef_version:_version,...bare}=cef;
    expect(read('cef',bare,{suser:'admin'})('dst')).toEqual([['dstip','REVIEW']]);
    // A sparse port still needs TCP or UDP named by its record; a destination still needs an address.
    const {proto:_proto,...noProtocol}=cef;
    expect(read('cef',noProtocol,{cef_version:'0',suser:'admin'})('dpt')).toEqual([['dstport','REVIEW']]);
    expect(read('cef',{...cef,dst:'db01.example.com'},{cef_version:'0',suser:'admin'})('dst')).toEqual([['dstip','REVIEW']]);
    // A key the specification does not define keeps the full-coverage rule.
    expect(read('cef',{...cef,sport:'40000'},{cef_version:'0',suser:'admin'})('sport')).toEqual([['srcport','REVIEW']]);
  });
});
