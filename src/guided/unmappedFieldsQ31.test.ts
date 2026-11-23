import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';

// Owner decision Q3-1 (2026-11-24): every field the reader extracted is kept, also one the sample never showed.
// Repro of the third independent audit (Q3-1) and the cases the decision lists. SYNTHETIC lines.
const cap={authoring:{
  extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  strictMixedRequiresExplicitAllowlist:true,
  strictMixedSingleLineFamilies:['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
function journey(source:string){
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(source,'single-line');
  const ready=prepareAutoParserDraft(source,draft,preview(source,draft),ledger,assessEnvelopeCompilation(ledger,cap));
  if(!ready.ok)throw new Error(ready.reason);
  return ready.draft;
}
const vendorOf=(out:Record<string,unknown>)=>out['Demo Local Draft'] as Record<string,unknown>;
const run=(draft:ReturnType<typeof journey>,lines:string[])=>preview(lines.join('\n'),draft).events;

describe('Q3-1: a field the sample never showed is kept',()=>{
  it('keeps a new key=value key in the vendor namespace and the event stays FULL',()=>{
    const draft=journey(['srcip=10.1.1.1 dstip=10.2.2.2 action=allow','srcip=10.1.1.3 dstip=10.2.2.4 action=deny'].join('\n'));
    expect(draft.preserveUnmapped).toBe(true);
    const [event]=run(draft,['srcip=10.1.1.5 dstip=10.2.2.6 action=allow newkey=zzz']);
    expect(event!.parseStatus).toBe('FULL');
    expect(event!.normalizedOk).toBe(true);
    expect(event!.normalized).toMatchObject({srcip:'10.1.1.5',dstip:'10.2.2.6'});
    expect(vendorOf(event!.normalized).newkey).toBe('zzz');
  });
  it('keeps a key of another family at another path (root vs body.*), audit Q3-1',()=>{
    const sample=['<134>Oct 12 01:02:05 fw01 src=10.5.5.6 dst=203.0.113.21 sport=2001 dport=80 action=deny user=bob',
      '<134>Oct 12 01:02:06 fw01 src=10.5.5.7 dst=203.0.113.22 sport=2002 dport=443 action=allow user=amy',
      '{"user":"alice","srcip":"10.1.1.1","dstip":"10.2.2.2"}','{"user":"carl","srcip":"10.1.1.2","dstip":"10.2.2.3"}'];
    const draft=journey(sample.join('\n'));
    const events=run(draft,[sample[0]+' srcip=10.9.9.9','{"user":"alice","srcip":"10.1.1.1","sport":"2001","action":"deny"}']);
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    expect(JSON.stringify(events[0]!.normalized)).toContain('"10.9.9.9"');
    expect(events[0]!.normalized.srcip).not.toBe('10.9.9.9');
    expect(JSON.stringify(events[1]!.normalized)).toContain('"2001"');
    expect(JSON.stringify(events[1]!.normalized)).toContain('"deny"');
  });
  it('keeps the same key in the header and in the body as two fields',()=>{
    const draft=journey(['<14>1 2026-10-12T01:02:03Z host5 app 1 - - srcip=10.1.1.1 action=allow',
      '<14>1 2026-10-12T01:02:04Z host5 app 1 - - srcip=10.1.1.2 action=deny'].join('\n'));
    const [event]=run(draft,['<14>1 2026-10-12T01:02:05Z host5 app 1 - - srcip=10.1.1.3 action=allow syslog_hostname=inner7']);
    expect(event!.parseStatus).toBe('FULL');
    expect(event!.normalized.hostname??JSON.stringify(event!.normalized)).toContain('host5');
    expect(JSON.stringify(vendorOf(event!.normalized))).toContain('"inner7"');
  });
  it('keeps a new key named like a mapped vendor field apart from it',()=>{
    const draft=journey(['{"a":{"user":"x1"},"n":1}','{"a":{"user":"x2"},"n":2}'].join('\n'));
    const [event]=run(draft,['{"a":{"user":"x3"},"n":3,"user":"y3"}']);
    expect(event!.parseStatus).toBe('FULL');
    const text=JSON.stringify(event!.normalized);
    expect(text).toContain('"x3"');
    expect(text).toContain('"y3"');
  });
  it('keeps arrays, nested objects, special characters and non-ASCII names and values',()=>{
    const draft=journey(['{"srcip":"10.1.1.1","act":"allow"}','{"srcip":"10.1.1.2","act":"deny"}'].join('\n'));
    const [event]=run(draft,['{"srcip":"10.1.1.3","act":"allow","tags":["a","b"],"geo":{"city":"서울","zip":"04524"},"사용자":"김민수","msg":"a=b \\"q\\" \\\\ ü"}']);
    expect(event!.parseStatus).toBe('FULL');
    const vendor=vendorOf(event!.normalized);
    expect(vendor.tags).toBe('["a","b"]');
    expect(vendor.geo).toEqual({city:'서울',zip:'04524'});
    expect(vendor['사용자']).toBe('김민수');
    expect(vendor.msg).toBe('a=b "q" \\ ü');
  });
  it('reads every event on its own, whatever the order',()=>{
    const draft=journey(['srcip=10.1.1.1 dstip=10.2.2.2 action=allow','srcip=10.1.1.3 dstip=10.2.2.4 action=deny'].join('\n'));
    const a='srcip=10.1.1.5 dstip=10.2.2.6 action=allow k1=v1',b='srcip=10.1.1.7 dstip=10.2.2.8 action=deny k2=v2';
    const forward=run(draft,[a,b]).map(event=>event.normalized),reverse=run(draft,[b,a]).map(event=>event.normalized);
    expect(reverse).toEqual([forward[1],forward[0]]);
    expect(vendorOf(forward[0]!).k2).toBeUndefined();
    expect(vendorOf(forward[1]!).k1).toBeUndefined();
  });
  it('passes the decision to the backend project',()=>{
    const converted=toBackendProject(journey(['srcip=10.1.1.1 action=allow','srcip=10.1.1.2 action=deny'].join('\n')));
    expect(converted.ok).toBe(true);
    if(converted.ok)expect(converted.project.normalization.preserveUnmapped).toBe(true);
  });
});
