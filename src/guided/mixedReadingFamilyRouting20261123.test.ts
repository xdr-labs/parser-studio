import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import type {BackendCapabilities} from './backendCapabilities';
import {inspectEventProfile,READING_FAMILY_DISCRIMINATOR,validateEventProfiles} from './multiEventRouting';

// Golden case mixed_envelope_cef_kv (final audit corpus), SYNTHETIC lines: an RFC 5424 CEF line and an RFC 3164
// key=value line. The Auto Parser reads such a sample with the mixed parser (Analyze Logs -> Review Fields), not
// with Generic Structural, so the per-family mapping of familyRoutedOtherFamilyNames20261123 never reached the
// user: the journey kept srcip/dstip/srcport/dstport of the CEF line and srcport/dstport of the key=value line
// out of the official fields.
const CEF='<165>1 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dst=198.51.100.4 spt=40000 dpt=443 act=deny';
const KV='<134>Oct 12 01:02:05 fw01 date=2026-10-12 time=01:02:05 srcip=10.5.5.6 srcport=2001 dstip=203.0.113.21 dstport=80 action=deny policyid=9';

function journey(source:string){
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(source,'single-line');
  const compiler=assessEnvelopeCompilation(ledger,cap);
  const ready=prepareAutoParserDraft(source,draft,preview(source,draft),ledger,compiler);
  if(!ready.ok)throw new Error(ready.reason);
  return ready.draft;
}
// The allowlisted one-line families of the backend capabilities (backend/src/capabilities.ts).
const cap={authoring:{
  extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  strictMixedRequiresExplicitAllowlist:true,
  strictMixedSingleLineFamilies:['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const tuple=(out:Record<string,unknown>)=>[out.srcip,out.dstip,out.srcport,out.dstport];

describe('Auto Parser journey of a mixed sample maps each reading family on its own',()=>{
  it('maps the network tuple of both families (journey path)',()=>{
    const source=[CEF,KV].join('\n');
    const draft=journey(source);
    expect(draft.format).toBe('mixed');
    expect(draft.eventProfiles?.discriminator).toBe(READING_FAMILY_DISCRIMINATOR);
    const events=preview(source,draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    expect(events.map(event=>tuple(event.normalized))).toEqual([
      ['192.0.2.11','198.51.100.4',40000,443],['10.5.5.6','203.0.113.21',2001,80]]);
    expect(events.map(event=>event.normalized.parserstudio_event_family)).toEqual(['rfc5424_cef','rfc3164_kv']);
    // Every source value of each line is still in its output (official field or vendor namespace).
    for(const [index,line] of [CEF,KV].entries()){
      const text=JSON.stringify(events[index]!.normalized);
      for(const value of ['deny',index?'fw01':'edge',index?'9':'Blocked'])expect(text,line).toContain(JSON.stringify(value));
    }
  });

  it('does not depend on the order of the lines',()=>{
    const source=[KV,CEF].join('\n');
    const events=preview(source,journey(source)).events;
    expect(events.map(event=>tuple(event.normalized))).toEqual([
      ['10.5.5.6','203.0.113.21',2001,80],['192.0.2.11','198.51.100.4',40000,443]]);
  });

  it('converts to a backend project routed by the reading family (backend validation: mixed-reading-family-native test)',()=>{
    const draft=journey([CEF,KV].join('\n'));
    const converted=toBackendProject(draft);
    expect(converted.ok).toBe(true);
    if(!converted.ok)return;
    expect(converted.project.extraction).toMatchObject({format:'mixed',mixedFormats:['rfc3164_kv','rfc5424_cef']});
    expect(converted.project.normalization.eventProfiles?.discriminator).toBe('@reading_family');
    expect(converted.project.normalization.eventProfiles?.variants.map(variant=>variant.equals).sort())
      .toEqual(['rfc3164_kv','rfc5424_cef']);
  });

  it('never takes the family from a field of the event',()=>{
    const config=journey([CEF,KV].join('\n')).eventProfiles!;
    expect(validateEventProfiles(config)).toBeNull();
    // A source field spelled like the discriminator selects nothing; only the reading does.
    expect(inspectEventProfile({'@reading_family':'rfc3164_kv'},config).profile).toBeNull();
    expect(inspectEventProfile({},config,'rfc3164_kv').name).toBe('rfc3164_kv');
  });

  it('keeps one shared mapping set when every family reads the same meaning from the same source',()=>{
    const source=['srcip=10.0.0.1 dstip=10.0.0.2 action=allow','{"srcip":"10.0.0.3","dstip":"10.0.0.4","action":"deny"}'].join('\n');
    const draft=journey(source);
    expect(draft.format).toBe('mixed');
    expect(draft.eventProfiles).toBeUndefined();
  });
});
