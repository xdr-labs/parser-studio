import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';
import {compilerDraftContract} from './contract';

// Final independent re-audit of 62263b3 (2026-11-24), H-1, for the preview and the UI contract; the backend side is
// backend/test/unmapped-fields-reaudit-20261124.test.ts. SYNTHETIC lines.
const cap={authoring:{extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const SAMPLE=['srcip=10.1.1.1 dstip=10.2.2.2 action=allow user=bob','srcip=10.1.1.3 dstip=10.2.2.4 action=deny user=amy'].join('\n');
function journey():ParserDraft{
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(SAMPLE,'single-line');
  const ready=prepareAutoParserDraft(SAMPLE,draft,preview(SAMPLE,draft),ledger,assessEnvelopeCompilation(ledger,cap));
  if(!ready.ok)throw new Error(ready.reason);
  expect(ready.draft.preserveUnmapped).toBe(true);
  return {...ready.draft,vendor:'acme'};
}
const contractErrors=(draft:ParserDraft)=>{const result=compilerDraftContract(draft);return result.ok?[]:result.errors;};

describe('H-1: a top or ns mapping never writes into the vendor namespace while fields are kept',()=>{
  it.each(['acme.src','acme','acme.parserstudio_unmapped.x'])('refuses %s for every event and in the UI contract',target=>{
    const base=journey();
    const official=base.mappings.find(rule=>rule.source==='srcip')!;
    expect(base.guided!.groups[official.id]).not.toBe('vendor_fields');
    const draft={...base,mappings:base.mappings.map(rule=>rule===official?{...rule,target}:rule)};
    // Also an event with no field to keep: the refusal must not depend on what the event holds.
    for(const line of ['srcip=10.1.1.5 dstip=10.2.2.6 action=allow user=carl x=1','srcip=10.1.1.5 dstip=10.2.2.6 action=allow user=carl'])
      expect(preview(line,draft).events[0]!.diagnostics.map(item=>item.code),line).toContain('TARGET_COLLISION');
    expect(contractErrors(draft)).toContain('Reserved destination: '+target);
    // Without the decision the target is free, as before.
    const {preserveUnmapped:_,...plain}=draft;
    expect(contractErrors(plain)).not.toContain('Reserved destination: '+target);
  });
  it('still accepts a top target outside the vendor namespace',()=>{
    const base=journey();
    const official=base.mappings.find(rule=>rule.source==='srcip')!;
    const draft={...base,mappings:base.mappings.map(rule=>rule===official?{...rule,target:'custom.src'}:rule)};
    expect(preview('srcip=10.1.1.5 dstip=10.2.2.6 action=allow user=carl',draft).events[0]!.diagnostics.map(item=>item.code))
      .not.toContain('TARGET_COLLISION');
  });
});
