import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';
import {compilerDraftContract} from './contract';

// Repro tests of the independent audit of 2b6602c (2026-11-24, G-2..G-4) for the preview and the UI contract; the
// backend side is backend/test/unmapped-fields-audit-2b6602c.test.ts. SYNTHETIC lines.
const cap={authoring:{extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const SAMPLE=['{"type":"a","srcip":"10.1.1.1","dstip":"10.2.2.2","action":"allow","user":"bob"}',
  '{"type":"a","srcip":"10.1.1.3","dstip":"10.2.2.4","action":"deny","user":"amy"}'].join('\n');
const LINE='{"type":"a","srcip":"10.1.1.5","dstip":"10.2.2.6","action":"allow","user":"carl","zone":"z3","x":"newx"}';
function journey(vendor='acme'):ParserDraft{
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(SAMPLE,'single-line');
  const ready=prepareAutoParserDraft(SAMPLE,draft,preview(SAMPLE,draft),ledger,assessEnvelopeCompilation(ledger,cap));
  if(!ready.ok)throw new Error(ready.reason);
  expect(ready.draft.preserveUnmapped).toBe(true);
  return {...ready.draft,vendor};
}
function officialOnly(draft:ParserDraft):ParserDraft{
  return {...draft,mappings:draft.mappings.filter(rule=>(draft.guided!.groups[rule.id]??'vendor_fields')!=='vendor_fields')};
}
function withEnrichment(draft:ParserDraft,rule:Record<string,unknown>):ParserDraft{
  return {...draft,guided:{...draft.guided!,enrichment:[rule] as never}};
}
const contractErrors=(draft:ParserDraft)=>{const result=compilerDraftContract(draft);return result.ok?[]:result.errors;};
const codes=(line:string,draft:ParserDraft)=>preview(line,draft).events[0]!.diagnostics.map(item=>item.code);

describe('G-2: an enrichment never writes the reserved parserstudio_unmapped object',()=>{
  it.each([
    ['a constant',{operator:'set_const',target:'acme.parserstudio_unmapped.foo',value:'fabricated'}],
    ['a copy of a mapped field',{operator:'copy',source:'srcip',target:'acme.parserstudio_unmapped.srcip'}],
    ['the object itself',{operator:'set_const',target:'acme.parserstudio_unmapped',value:'fabricated'}],
  ])('refuses %s in the preview and in the UI contract',(_,rule)=>{
    const draft=withEnrichment(journey(),rule);
    for(const line of [LINE,SAMPLE.split('\n')[0]!]){
      const [event]=preview(line,draft).events;
      expect(event!.diagnostics.map(item=>item.code)).toContain('ENRICHMENT_TARGET');
      expect(JSON.stringify(event!.normalized)).not.toContain('fabricated');
      expect(JSON.stringify((event!.normalized.acme as Record<string,unknown>|undefined)?.parserstudio_unmapped??{}))
        .not.toContain('"srcip"');
    }
    expect(contractErrors(draft)).toContain('Unsafe enrichment output at step 1');
  });
  it('still accepts an enrichment target elsewhere in the vendor namespace',()=>{
    const draft=withEnrichment(journey(),{operator:'set_const',target:'acme.site',value:'kr'});
    expect(codes(LINE,draft)).not.toContain('ENRICHMENT_TARGET');
    expect(contractErrors(draft)).not.toContain('Unsafe enrichment output at step 1');
  });
});

describe('G-3: with fields kept, the manufacturer never names a system-owned root',()=>{
  it.each(['msg_origin','stellar_log_index','parserstudio_transport','parserstudio_event_family'])(
    'refuses %s without vendor fields in the UI contract, as the preview does',vendor=>{
      const draft=officialOnly(journey(vendor));
      expect(codes(LINE,draft)).toContain('TARGET_COLLISION');
      expect(contractErrors(draft)).toContain('Manufacturer conflicts with a reserved parser output namespace.');
      const {preserveUnmapped:_,...unchanged}=draft;
      expect(contractErrors(unchanged)).not.toContain('Manufacturer conflicts with a reserved parser output namespace.');
    });
});

describe('G-4: with fields kept, an enrichment never writes the bare manufacturer name',()=>{
  it('refuses it for every event, with or without a field to keep, and in the UI contract',()=>{
    const draft=withEnrichment(officialOnly(journey()),{operator:'set_const',target:'acme',value:'x'});
    const mapped=new Set(draft.mappings.map(rule=>rule.source));
    const onlyMapped=JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(LINE) as Record<string,unknown>)
      .filter(([key])=>mapped.has(key))));
    for(const line of [LINE,onlyMapped]){
      const [event]=preview(line,draft).events;
      expect(event!.diagnostics.map(item=>item.code),line).toContain('ENRICHMENT_TARGET');
      expect(event!.normalized.acme).not.toBe('x');
    }
    expect(contractErrors(draft)).toContain('Unsafe enrichment output at step 1');
    // Without the decision the manufacturer name is free and the constant is written, as before.
    const {preserveUnmapped:_,...unchanged}=draft;
    expect(preview(LINE,unchanged).events[0]!.normalized.acme).toBe('x');
    expect(contractErrors(unchanged)).not.toContain('Unsafe enrichment output at step 1');
  });
});

describe('a vendor mapping never writes parserstudio_unmapped (UI contract, as the preview and backend do)',()=>{
  it('refuses the target in the UI contract',()=>{
    const base=journey();
    const vendor=base.mappings.find(rule=>(base.guided!.groups[rule.id]??'vendor_fields')==='vendor_fields');
    if(!vendor)throw new Error('the journey has no vendor mapping');
    const draft={...base,mappings:base.mappings.map(rule=>rule===vendor?{...rule,target:'parserstudio_unmapped.'+rule.target}:rule)};
    expect(codes(LINE,draft)).toContain('TARGET_COLLISION');
    expect(contractErrors(draft)).toContain('Reserved destination: parserstudio_unmapped.'+vendor.target);
  });
});
