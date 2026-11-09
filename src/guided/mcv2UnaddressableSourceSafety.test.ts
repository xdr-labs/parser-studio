import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {createCanonicalMappingPlan} from './canonicalMappingPlan';

const cap={authoring:{extractionFormats:['kv','json','csv'],rfc5424BodyFormats:['raw','kv']},
  verification:{engineVerified:false,targetImportVerified:false}} as any;
function author(raw:string){
  const draft=createDraft();
  const suite=preview(raw,draft);
  const ledger=analyzeLogEnvelopes(raw,'single-line');
  const assessment=assessEnvelopeCompilation(ledger,cap);
  return prepareAutoParserDraft(raw,draft,suite,ledger,assessment);
}
describe('unaddressable source data accounting is not a destructive authoring veto',()=>{
  it('allows reviewed scalar mappings while counting non-addressable AWS WAF array elements',()=>{
    const raw=JSON.stringify({action:'BLOCK',httpRequest:{clientIp:'203.0.113.21',
      headers:[{name:'User-Agent',value:'curl/8.0'}]}});
    const result=author(raw);
    expect(result).toMatchObject({ok:true});
    if(!result.ok)return;
    const suite=preview(raw,result.draft);
    const plan=createCanonicalMappingPlan(suite,result.draft);
    expect(plan.unaddressableValues).toBeGreaterThan(0);
    expect(result.draft.mappings.some(mapping=>mapping.source.includes('headers.0'))).toBe(false);
    expect(suite.events[0]?.raw).toBe(raw);
  });
  it('does not block a reviewed comma-separated CSV because one empty source value has no scalar mapping',()=>{
    const raw='192.0.2.10,,443';
    const draft=createDraft();draft.format='csv';draft.csvColumns='src_ip,detail,dst_port';
    draft.mappings=[];
    const suite=preview(raw,draft);
    const ledger=analyzeLogEnvelopes(raw,'single-line');
    const assessment=assessEnvelopeCompilation(ledger,cap);
    if(assessment.status!=='DRAFT_COMPILABLE')return;
    const result=prepareAutoParserDraft(raw,draft,suite,ledger,assessment);
    expect(result).toMatchObject({ok:true});
  });
});
