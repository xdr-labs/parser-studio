import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {extractGenericStructural} from '../genericStructural';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';
import {isCarriedFamilyMapping,READING_FAMILY_DISCRIMINATOR} from './multiEventRouting';
import {mergeFamilyCandidate,projectFamilyDraft} from './familyScopedAssist';

// Repro tests of the independent audit of 2026-11-23 (changes after e78feb9). SYNTHETIC lines, built from the
// auditor's inputs.
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
const text=(value:unknown)=>JSON.stringify(value);

describe('F1: a family-routed draft keeps every source another family maps',()=>{
  // The RFC 3164 line carries user, the RFC 5424 line does not; at run time the RFC 5424 family sees user=alice
  // and the RFC 3164 family sees srcip. A mixed parser emits mapped sources only, so the routed variants dropped
  // both values from events still reported FULL.
  const S5424='<14>1 2026-10-12T01:02:03Z host5 app 1 - - srcip=10.1.1.1 dstip=10.2.2.2 srcport=1000 dstport=22 action=allow';
  const S3164='<134>Oct 12 01:02:05 fw01 src=10.5.5.6 dst=203.0.113.21 sport=2001 dport=80 action=deny user=bob';
  it('keeps user=alice of an RFC 5424 event and srcip of an RFC 3164 event',()=>{
    const draft=journey([S5424,S3164].join('\n'));
    expect(draft.eventProfiles?.discriminator).toBe(READING_FAMILY_DISCRIMINATOR);
    const runtime=[S5424+' user=alice',S3164+' srcip=10.9.9.9'];
    const events=preview(runtime.join('\n'),draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    expect(text(events[0]!.normalized)).toContain('"alice"');
    expect(text(events[1]!.normalized)).toContain('"10.9.9.9"');
    // The key the RFC 3164 sample never showed is kept as a vendor field, not as an official one.
    expect(events[1]!.normalized.srcip).not.toBe('10.9.9.9');
    // The sample itself reads as before.
    const sample=preview([S5424,S3164].join('\n'),draft).events;
    expect(sample.map(event=>[event.normalized.srcip,event.normalized.dstip])).toEqual([
      ['10.1.1.1','10.2.2.2'],[sample[1]!.normalized.srcip,sample[1]!.normalized.dstip]]);
    expect(text(sample[1]!.normalized)).toContain('"bob"');
  });
});

describe('F1: the family-scoped ChatGPT path keeps the carried sources of a family',()=>{
  const S5424='<14>1 2026-10-12T01:02:03Z host5 app 1 - - srcip=10.1.1.1 dstip=10.2.2.2 srcport=1000 dstport=22 action=allow';
  const S3164='<134>Oct 12 01:02:05 fw01 src=10.5.5.6 dst=203.0.113.21 sport=2001 dport=80 action=deny user=bob';
  it('leaves a carried mapping out of the single-family draft and keeps it on merge',()=>{
    const sample=[S5424,S3164].join('\n');
    const draft=journey(sample);
    const variant=draft.eventProfiles!.variants.find(item=>item.name==='rfc5424_kv')!;
    const carried=variant.mappings.filter(isCarriedFamilyMapping);
    expect(carried.map(rule=>rule.source)).toContain('body.user');
    for(const rule of carried)expect(draft.guided!.groups[rule.id]).toBe('vendor_fields');
    const single=projectFamilyDraft(draft,'rfc5424_kv')!;
    expect(single.mappings.some(isCarriedFamilyMapping)).toBe(false);
    // A reviewed result for the family: the destination port of its own records as an official field.
    const port=single.mappings.find(rule=>rule.source==='body.dstport')!;
    const candidate={...single,mappings:single.mappings.map(rule=>rule===port?{...rule,target:'dstport',type:'port' as const}:rule),
      guided:{...single.guided!,groups:{...single.guided!.groups,[port.id]:'top_fields' as const}}};
    const merged=mergeFamilyCandidate(draft,'rfc5424_kv',candidate,preview(sample,draft));
    expect(merged.ok,JSON.stringify(merged)).toBe(true);
    if(!merged.ok)return;
    const after=merged.draft.eventProfiles!.variants.find(item=>item.name==='rfc5424_kv')!;
    expect(after.mappings.filter(isCarriedFamilyMapping).map(rule=>rule.source).sort())
      .toEqual(carried.map(rule=>rule.source).sort());
    const events=preview(S5424+' user=alice',merged.draft).events;
    expect(events[0]!.parseStatus).toBe('FULL');
    expect(text(events[0]!.normalized)).toContain('"alice"');
  });
});

describe('F2: a JSON or key=value body is never read with CEF meanings',()=>{
  it('keeps dst of a JSON Syslog body that names a key cef_version out of the official fields',()=>{
    const source=['<14>1 2026-10-12T01:02:03Z host5 app 1 - - {"cef_version":"0","dst":"198.51.100.2","act":"deny"}',
      '<14>1 2026-10-12T01:02:04Z host5 app 1 - - {"cef_version":"0","suser":"admin"}'].join('\n');
    const events=preview(source,journey(source)).events;
    expect(events[0]!.normalized.dstip).toBeUndefined();
    expect(text(events[0]!.normalized)).toContain('"198.51.100.2"');
  });
  it('keeps dst of a key=value Syslog body that names a key cef_version out of the official fields',()=>{
    const source=['<14>1 2026-10-12T01:02:03Z host5 app 1 - - cef_version=0 dst=198.51.100.2 act=deny',
      '<14>1 2026-10-12T01:02:04Z host5 app 1 - - cef_version=0 suser=admin'].join('\n');
    const events=preview(source,journey(source)).events;
    expect(events[0]!.normalized.dstip).toBeUndefined();
    expect(text(events[0]!.normalized)).toContain('"198.51.100.2"');
  });
  it('still maps dst of a CEF Syslog body that only some records carry',()=>{
    const source=['<14>1 2026-10-12T01:02:03Z host5 app 1 - - CEF:0|Synthetic|FW|1|42|Blocked|8|dst=198.51.100.2 act=deny',
      '<14>1 2026-10-12T01:02:04Z host5 app 1 - - CEF:0|Synthetic|FW|1|43|Login|3|suser=admin'].join('\n');
    const events=preview(source,journey(source)).events;
    expect(events[0]!.normalized.dstip).toBe('198.51.100.2');
    expect(events[1]!.normalized.dstip).toBeUndefined();
  });
});

describe('F3: the WatchGuard Traffic Monitor layout has ports for TCP and UDP only',()=>{
  const ICMP='2024-04-01 23:39:46 Deny 10.0.1.131 10.0.1.1 echo-request/icmp 8 0 Trusted Firebox Denied 84 64 (Ping-00) proc_id="firewall" rc="101" msg_id="3000-0148"';
  const UDP='2024-03-29 18:00:54 Allow 10.0.1.2 192.0.2.53 dns/udp 53000 53 Trusted External Allowed 72 63 (DNS-proxy.1-00) proc_id="firewall" rc="100" msg_id="3000-0148"';
  it('does not read two numbers after ICMP as a source and a destination port',()=>{
    const result=extractGenericStructural(ICMP,undefined,'dedicated');
    const fields=result.fields as Record<string,Record<string,unknown>|undefined>;
    expect(fields.generic?.mode).not.toBe('watchguard_traffic_monitor');
    expect(fields.watchguard?.src_port).toBeUndefined();
    expect(fields.watchguard?.dst_port).toBeUndefined();
    // The line is declined (not reported as read), so its original text stays the record of the event.
    expect(result.fields).toEqual({});
    expect(result.errors.length).toBeGreaterThan(0);
  });
  it('reads the ports of a UDP line',()=>{
    const fields=extractGenericStructural(UDP,undefined,'dedicated').fields as Record<string,Record<string,unknown>>;
    expect(fields.generic!.mode).toBe('watchguard_traffic_monitor');
    expect(fields.watchguard).toMatchObject({protocol:'udp',src_port:'53000',dst_port:'53'});
  });
});
