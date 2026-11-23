import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {extractGenericStructural} from '../genericStructural';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';
import {isCarriedFamilyMapping,READING_FAMILY_DISCRIMINATOR} from './multiEventRouting';
import {mergeFamilyCandidate,projectFamilyDraft} from './familyScopedAssist';
import {regexReadsUncapturedText} from './regexSourceCoverage';

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

describe('F1: a source is carried only into a family whose reading can hold it',()=>{
  // Golden-like PAN-OS TRAFFIC CSV and CEF records (familyRoutedMappings20261123): a PAN-OS record never has the
  // body.* container of a CEF record, nor a CEF record the generic.fields.* of a PAN-OS record.
  const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
  const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
  it('carries nothing between a PAN-OS CSV family and a CEF family',()=>{
    const built=buildAutomaticGenericStructuralDraft([PAN,CEF].join('\n'),createDraft())!;
    for(const variant of built.draft.eventProfiles!.variants)
      expect(variant.mappings.filter(isCarriedFamilyMapping).map(rule=>rule.source)).toEqual([]);
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

// Re-audit of 2026-11-23 (second independent audit, ad53b51 and e65baa6). SYNTHETIC lines from the auditor.
describe('re-audit Q2-1: a mixed family carries a source whatever container its sample showed',()=>{
  it('keeps a root key of a JSON event and a dotted key of a key=value event',()=>{
    const draft=journey(['{"net":{"srcip":"10.1.1.1","dstip":"10.2.2.2"}}','srcip=10.5.5.6 dstip=10.6.6.6 user=bob'].join('\n'));
    expect(draft.eventProfiles?.discriminator).toBe(READING_FAMILY_DISCRIMINATOR);
    const events=preview(['{"net":{"srcip":"10.1.1.9","dstip":"10.2.2.9"},"user":"alice"}',
      'srcip=10.5.5.6 dstip=10.6.6.6 user=bob net.srcip=10.7.7.7'].join('\n'),draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    expect(text(events[0]!.normalized)).toContain('"alice"');
    expect(text(events[1]!.normalized)).toContain('"10.7.7.7"');
    expect(events[1]!.normalized.srcip).toBe('10.5.5.6');
  });
});

describe('re-audit Q2-2: a carried source keeps its text',()=>{
  it('does not type a key=value value by the JSON values of another family',()=>{
    const draft=journey(['{"srcip":"10.1.1.1","dstip":"10.2.2.2","bytes":100,"ok":true}',
      '{"srcip":"10.1.1.3","dstip":"10.2.2.4","bytes":200,"ok":false}','src=10.5.5.6 dst=203.0.113.21 action=deny'].join('\n'));
    expect(draft.eventProfiles?.discriminator).toBe(READING_FAMILY_DISCRIMINATOR);
    const base='src=10.5.5.6 dst=203.0.113.21 action=deny';
    const events=preview([base+' bytes=007 ok=yes',base+' bytes=abc',base+' ok=true bytes=5'].join('\n'),draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL','FULL']);
    expect(events.map(event=>event.normalizedOk)).toEqual([true,true,true]);
    expect(text(events[0]!.normalized)).toContain('"007"');
    expect(text(events[0]!.normalized)).toContain('"yes"');
    expect(text(events[1]!.normalized)).toContain('"abc"');
    expect(text(events[2]!.normalized)).toContain('"true"');
  });
});

describe('re-audit Q2-3: an optional literal outside a capture reads uncaptured text',()=>{
  it('rejects (?:DENIED )? and keeps optional white space allowed',()=>{
    expect(regexReadsUncapturedText('^(?<a>[A-Z0-9]+) (?:DENIED )?(?<b>[a-z0-9]+)$')).toBe(true);
    expect(regexReadsUncapturedText('^(?<a>[A-Z0-9]+) (?:DENIED){0,1}(?<b>[a-z0-9]+)$')).toBe(true);
    expect(regexReadsUncapturedText('^(?<a>[A-Z0-9]+)(?: )?(?<b>[a-z0-9]+)$')).toBe(false);
    expect(regexReadsUncapturedText('^(?<a>[A-Z0-9]+) (?:(?<d>DENIED) )?(?<b>[a-z0-9]+)$')).toBe(false);
  });
});

describe('re-audit Q2-4 and Q2-5: a family result may not drop a value of the family',()=>{
  const S5424='<14>1 2026-10-12T01:02:03Z host5 app 1 - - srcip=10.1.1.1 dstip=10.2.2.2 srcport=1000 dstport=22 action=allow';
  const S3164='<134>Oct 12 01:02:05 fw01 src=10.5.5.6 dst=203.0.113.21 sport=2001 dport=80 action=deny user=bob';
  const sample=[S5424,S3164].join('\n');
  it('refuses a result that writes the vendor output of a carried source',()=>{
    const draft=journey(sample);
    const single=projectFamilyDraft(draft,'rfc5424_kv')!;
    const port=single.mappings.find(rule=>rule.source==='body.dstport')!;
    const candidate={...single,mappings:single.mappings.map(rule=>rule===port?{...rule,target:'user'}:rule),
      guided:{...single.guided!,groups:{...single.guided!.groups,[port.id]:'vendor_fields' as const}}};
    expect(mergeFamilyCandidate(draft,'rfc5424_kv',candidate,preview(sample,draft)))
      .toEqual({ok:false,reason:'DESTINATION_COLLISION'});
  });
  it('refuses a result that leaves out a source the family maps',()=>{
    const draft=journey(sample);
    const single=projectFamilyDraft(draft,'rfc3164_kv')!;
    expect(single.mappings.some(rule=>rule.source==='body.user')).toBe(true);
    const candidate={...single,mappings:single.mappings.filter(rule=>rule.source!=='body.user')};
    expect(mergeFamilyCandidate(draft,'rfc3164_kv',candidate,preview(sample,draft)))
      .toEqual({ok:false,reason:'FAMILY_SOURCE_REMOVED'});
  });
});

// Third independent audit of 2026-11-23 (bdf76cd). SYNTHETIC patterns from the auditor.
describe('re-audit Q3-2 and Q3-3: repeated captures and white-space escapes in a ChatGPT regex',()=>{
  it('rejects a capture inside a repeated group: only its last repetition is kept',()=>{
    expect(regexReadsUncapturedText('^(?<cmd>\\S+)(?: (?<flag>-[a-z]))*$')).toBe(true);
    expect(regexReadsUncapturedText('^(?<cmd>\\S+)(?: (?<flag>-[a-z])){2}$')).toBe(true);
    // The whole repeated text in one capture keeps every repetition.
    expect(regexReadsUncapturedText('^(?<cmd>\\S+)(?<flags>(?: -[a-z])*)$')).toBe(false);
  });
  it('counts \\x20, \\x09 and \\r as white space, and an optional quote or comma as data',()=>{
    expect(regexReadsUncapturedText('^(?<a>\\S+)(?:\\x20)?(?<b>\\S+)$')).toBe(false);
    expect(regexReadsUncapturedText('^(?<msg>.*?)\\r?$')).toBe(false);
    expect(regexReadsUncapturedText('^(?<a>\\S+) "?(?<user>[^" ]+)"? (?<b>\\S+)$')).toBe(true);
    expect(regexReadsUncapturedText('^(?<a>[^,]+),?(?<b>\\S+)$')).toBe(true);
  });
});
