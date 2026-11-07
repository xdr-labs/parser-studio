import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { createDraft } from '../model';
import { preview } from '../parser';
import { createBrowserEvidence } from './browserEvidence';
import { compareBrowserEvidence } from './browserEvidenceComparison';

const sample = [
  '{"action":"allow","src_ip":"198.51.100.21","dst_port":443}',
  '{"action":"deny","src_ip":"invalid-ip-BRANCH_SECRET","dst_port":22}',
].join('\n');

describe('same-fixture offline browser test evidence comparison', () => {
  beforeEach(() => vi.stubGlobal('crypto',webcrypto));
  afterEach(() => vi.unstubAllGlobals());

  async function report(type:'string'|'ip') {
    const draft=createDraft();draft.format='json';
    draft.mappings[0].type=type;
    return createBrowserEvidence({sample,draft,suite:preview(sample,draft)});
  }

  it('compares the same fixture across two draft revisions and finds one regressed event',async()=>{
    const before=await report('string');
    const after=await report('ip');
    const diff=compareBrowserEvidence(before,after);
    expect(diff).toEqual({
      sameSample:true, sameDraft:false,
      baselineEvents:2,currentEvents:2,
      improved:0,regressed:1,unchanged:1,changedDiagnostics:1,
      changed:[{event:2,line:2,change:'regressed',fromNormalized:true,toNormalized:false}],
    });
    expect(JSON.stringify(diff)).not.toContain('198.51.100.21');
    expect(JSON.stringify(diff)).not.toContain('BRANCH_SECRET');
    expect(compareBrowserEvidence(after,before)).toMatchObject({improved:1,regressed:0});
  });

  it('retains canonical enrichment stages and protocol failures in safe evidence',async()=>{
    const draft=createDraft();
    draft.format='json';
    draft.mappings=[
      {id:'user',source:'user',target:'username',type:'string'},
      {id:'p',source:'p',target:'proto',type:'integer'},
    ];
    draft.guided={...draft.guided!,groups:{user:'top_fields',p:'top_fields'},
      enrichment:[{id:'name',operator:'set_const',source:'',target:'proto_name',value:'UDP'}]};
    const raw=JSON.stringify({user:'alice',p:6});
    const report=await createBrowserEvidence({sample:raw,draft,suite:preview(raw,draft)});
    expect(report.events[0]?.diagnostics).toContainEqual({
      stage:'enrichment',severity:'error',code:'PROTOCOL_CONFLICT',
    });
    expect(compareBrowserEvidence(report,report)).toMatchObject({
      sameSample:true,unchanged:1,changedDiagnostics:0,
    });
    expect(JSON.stringify(report)).not.toContain('alice');
  });

  it('identical evidence is an unchanged, non-native report',async()=>{
    const original=await report('ip');
    expect(compareBrowserEvidence(original,original)).toMatchObject({
      sameSample:true,sameDraft:true,improved:0,regressed:0,unchanged:2,changedDiagnostics:0,changed:[],
    });
  });

  it('refuses comparisons across different underlying logs or event shapes',async()=>{
    const old=await report('string'),cur=await report('ip');
    const differentSample=structuredClone(old);
    differentSample.source.sampleSha256='f'.repeat(64);
    expect(()=>compareBrowserEvidence(differentSample,cur)).toThrow(/SHA-256|different/i);
    const reordered=structuredClone(old);
    reordered.events[0].number=2;
    expect(()=>compareBrowserEvidence(reordered,cur)).toThrow();
    const noEvents=structuredClone(old);
    noEvents.events=[];
    expect(()=>compareBrowserEvidence(noEvents,cur)).toThrow();
  });

  it('rejects untrusted raw fields, bogus verification flags, wrong schemas and malformed metadata',async()=>{
    const valid=await report('ip');
    const bad=[
      {...valid,reportSchema:'future.v2'},
      {...valid,compatibility:{nativeFluentdVerified:true,stellarTargetVerified:false}},
      {...valid,privacy:{...valid.privacy,rawLogsIncluded:true}},
      {...valid,events:valid.events.map((event,i)=>i===0?{...event,raw:'TOP_SECRET_RAW'}:event)},
      {...valid,events:valid.events.map((event,i)=>i===0?{...event,status:'customer-secret'}:event)},
      {...valid,source:{...valid.source,sampleSha256:'not-a-hash'}},
      {...valid,counts:{...valid.counts,total:55}},
    ];
    for(const baseline of bad){
      expect(()=>compareBrowserEvidence(baseline,valid)).toThrow();
    }
  });
});
