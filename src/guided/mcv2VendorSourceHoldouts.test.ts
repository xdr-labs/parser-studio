import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {createCanonicalMappingPlan} from './canonicalMappingPlan';
import {toBackendProject} from './backendAdapter';

const root='tests/fixtures/docs-practice-20261104/';
const cap={authoring:{extractionFormats:['kv','json','syslog_rfc5424'],rfc5424BodyFormats:['raw','kv']},
  verification:{engineVerified:false,targetImportVerified:false}} as any;
function author(filename:string){
  const raw=readFileSync(root+filename,'utf8').trimEnd();
  const draft=createDraft();
  const suite=preview(raw,draft);
  const ledger=analyzeLogEnvelopes(raw,'single-line');
  const assessment=assessEnvelopeCompilation(ledger,cap);
  const produced=prepareAutoParserDraft(raw,draft,suite,ledger,assessment);
  return {raw,draft,suite,ledger,assessment,produced};
}
const cases=[
  {name:'01-juniper-srx.log',ports:[[594,10400],[37233,161]],
    src:['10.0.0.1','10.0.0.26'],dst:['67.43.156.13','67.43.156.13']},
  {name:'04-fortigate-traffic.log',ports:[[44258,80],[58012,80]],
    src:['10.1.100.11','10.1.100.11'],dst:['185.244.31.158','23.59.154.35']},
  {name:'04-fortigate-threat.log',ports:[[44258,80],[46810,80]],
    src:['10.1.100.11','10.1.100.22'],dst:['185.244.31.158','172.16.200.55']},
];
describe('original vendor source logs: independent acceptance golden',()=>{
  it.each(cases)('retains source identity, approved tuple and compiler for $name',c=>{
    const result=author(c.name);
    expect(result.assessment.status).toBe('DRAFT_COMPILABLE');
    expect(result.produced).toMatchObject({ok:true});
    if(!result.produced.ok)return;
    const draft=result.produced.draft;
    const suite=preview(result.raw,draft);
    const plan=createCanonicalMappingPlan(suite,draft);
    expect(plan.contract).toBe('parser-studio.mapping-plan.v1');
    expect(plan.entries.length).toBe(plan.sourceCount);
    expect(new Set(plan.entries.map(e=>e.source)).size).toBe(plan.sourceCount);
    expect(suite.events).toHaveLength(c.ports.length);
    suite.events.forEach((event,i)=>{
      expect(event.raw).toBe(result.raw.split(/\r?\n/)[i]);
      expect(event.normalized).toMatchObject({srcip:c.src[i],dstip:c.dst[i],
        srcport:c.ports[i]?.[0],dstport:c.ports[i]?.[1]});
    });
    expect(toBackendProject(draft)).toMatchObject({ok:true});
    for(const target of ['srcport','dstport']){
      const official=draft.mappings.find(m=>m.target===target);
      expect(official).toMatchObject({authoring:{version:1,origin:'AUTO'}});
    }
  });
  it.each(['02-sophos-xg.log','06-panos-traffic-issue.log'])(
    'refuses to falsely certify incomplete/ambiguous raw source %s',name=>{
      const result=author(name);
      expect(result.assessment.status).not.toBe('DRAFT_COMPILABLE');
      expect(result.produced.ok).toBe(false);
      // A failure to author a DRAFT must never destroy the original source.
      expect(result.raw.length).toBeGreaterThan(40);
      expect(result.produced).not.toHaveProperty('draft');
    });
});
