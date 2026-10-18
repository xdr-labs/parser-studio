import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planAllFamilyAudit,summarizeAllFamilyAudit} from './familyAudit';
import {createAllFamilyAuditEvidence} from './familyAuditEvidence';

const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"secret":"CUSTOMER_SECRET_A"}',
  'action=deny src_ip=203.0.113.10 dst_port=22 username=PRIVATE_USER',
  '{"action":"deny","src_ip":"192.0.2.15","dst_port":80,"secret":"CUSTOMER_SECRET_B"}',
  'unrecognized raw PRIVATE_UNSUPPORTED_EVENT',
].join('\n');
function input(){
  const draft=createDraft();draft.format='json';
  const suite=preview(sample,draft);
  const plan=planAllFamilyAudit(sample,draft,suite);
  const results=plan.plans.map(p=>preview(p.sample,{...draft,format:p.format}));
  const report=summarizeAllFamilyAudit(plan,results);
  return {sample,draft,suite,report};
}
describe('metadata-only all-family audit download',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());

  it('exports deterministic source-SHA-bound counts and unknown lines without event bytes or sensitive values',async()=>{
    const data=input();
    const result=await createAllFamilyAuditEvidence(data);
    expect(result).toMatchObject({
      reportSchema:'parser-studio.browser-family-audit-evidence.v0.1',
      engine:'browser-preview',status:'DRAFT_ONLY',
      privacy:{rawLogsIncluded:false,normalizedValuesIncluded:false,diagnosticMessagesIncluded:false},
      compatibility:{nativeFluentdVerified:false,stellarTargetVerified:false,singleMixedFormatParserVerified:false},
      overview:{sourceEvents:4,reviewedEvents:3,unreviewableEvents:1},
      families:[{format:'json',sourceEvents:2},{format:'kv',sourceEvents:1}],
      unreviewable:[{originalLine:4,format:'unknown'}],
    });
    expect(result.source.sampleSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.source.draftSha256).toMatch(/^[a-f0-9]{64}$/);
    const json=JSON.stringify(result);
    for(const sensitive of ['CUSTOMER_SECRET_A','CUSTOMER_SECRET_B',
      'PRIVATE_USER','PRIVATE_UNSUPPORTED_EVENT','198.51.100.10','203.0.113.10',
      '"raw"','"source":"','"normalizedValues":']){
      expect(json).not.toContain(sensitive);
    }
    expect(await createAllFamilyAuditEvidence(data)).toEqual(result);
  });

  it('changes provenance on source edits but never carries the source bytes into metadata',async()=>{
    const first=input();
    const original=await createAllFamilyAuditEvidence(first);
    const source=first.sample.replace('CUSTOMER_SECRET_A','CHANGED_SECRET_A');
    const draft=createDraft();draft.format='json';
    const suite=preview(source,draft);
    const plan=planAllFamilyAudit(source,draft,suite);
    const report=summarizeAllFamilyAudit(plan,
      plan.plans.map(p=>preview(p.sample,{...draft,format:p.format})));
    const changed=await createAllFamilyAuditEvidence({sample:source,draft,suite,report});
    expect(changed.source.sampleSha256).not.toBe(original.source.sampleSha256);
    expect(JSON.stringify(changed)).not.toContain('CHANGED_SECRET_A');
  });

  it('rejects unsafe or inconsistent audit metadata and native proof spoofing',async()=>{
    const good=input();
    const invalid=[
      {...good.report,nativeFluentdVerified:true},
      {...good.report,sourceCount:500},
      {...good.report,reviewedCount:99},
      {...good.report,unreviewableEvents:[{originalLine:4,format:'PRIVATE_VALUE'}]},
      {...good.report,families:good.report.families.map(f=>({...f,counts:{...f.counts,total:99}}))},
      {...good.report,families:[{...good.report.families[0],format:'unknown'},good.report.families[1]]},
      {...good.report,rawLog:'CUSTOMER_SECRET_A'},
    ];
    for(const report of invalid){
      await expect(createAllFamilyAuditEvidence({...good,report} as typeof good)).rejects.toThrow();
    }
  });

  it('fails closed without secure browser WebCrypto or a matching full sample suite',async()=>{
    const value=input();
    vi.stubGlobal('crypto',null);
    await expect(createAllFamilyAuditEvidence(value)).rejects.toThrow(/SHA-256|secure/i);
    vi.stubGlobal('crypto',webcrypto);
    await expect(createAllFamilyAuditEvidence({...value,suite:{...value.suite,
      events:value.suite.events.slice(1)}})).rejects.toThrow();
  });
});
