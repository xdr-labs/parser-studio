import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {
  planAllFamilyAudit,summarizeAllFamilyAudit,
} from './familyAudit';

const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"secret":"CUSTOMER_SECRET_A"}',
  'action=deny src_ip=203.0.113.10 dst_port=22 username=PRIVATE_USER',
  '{"action":"deny","src_ip":"192.0.2.15","dst_port":80,"secret":"CUSTOMER_SECRET_B"}',
  'raw unrecognized log message with PRIVATE_UNSUPPORTED_CONTENT',
].join('\n');

describe('strict browser-only audit of all detected families (P0-B)',()=>{
  it('explicitly accounts for every recognized and unsupported source event without mutating a parser',()=>{
    const draft=createDraft();draft.format='json';
    const before=structuredClone(draft);
    const full=preview(sample,draft);
    const plan=planAllFamilyAudit(sample,draft,full);
    expect(plan.sourceCount).toBe(4);
    expect(plan.plans.map(p=>[p.format,p.originalLines])).toEqual([
      ['json',[1,3]],['kv',[2]],
    ]);
    expect(plan.unreviewableEvents).toEqual([
      {originalLine:4,format:'unknown'},
    ]);
    expect(plan.plans[0].sample).toContain('CUSTOMER_SECRET_A');
    expect(plan.plans[1].sample).toContain('PRIVATE_USER');
    const runs=plan.plans.map(item=>preview(item.sample,{...draft,format:item.format}));
    const report=summarizeAllFamilyAudit(plan,runs);
    expect(report).toMatchObject({
      contract:'parser-studio.browser-all-family-audit.v0.1',
      sourceCount:4,reviewedCount:3,unreviewableCount:1,
      browserOnly:true,nativeFluentdVerified:false,stellarExportVerified:false,
      notSingleParserProof:true,
      unreviewableEvents:[{originalLine:4,format:'unknown'}],
    });
    expect(report.families.map(f=>[f.format,f.selectedCount])).toEqual([['json',2],['kv',1]]);
    expect(report.families.flatMap(f=>f.perEvent.map(e=>e.originalLine)).sort()).toEqual([1,2,3]);
    expect(draft).toEqual(before);
    expect(sample).toContain('PRIVATE_UNSUPPORTED_CONTENT');
    for(const sensitive of ['CUSTOMER_SECRET_A','CUSTOMER_SECRET_B','PRIVATE_USER',
      'PRIVATE_UNSUPPORTED_CONTENT','198.51.100.10','203.0.113.10']){
      expect(JSON.stringify(report)).not.toContain(sensitive);
    }
  });

  it('rejects stale, truncated or tampered original evidence before any branch can silently disappear',()=>{
    const draft=createDraft();const full=preview(sample,draft);
    expect(()=>planAllFamilyAudit(sample+' extra',draft,full)).toThrow();
    const tampered=structuredClone(full);tampered.events[1].raw='malicious revision';
    expect(()=>planAllFamilyAudit(sample,draft,tampered)).toThrow();
    draft.guided={...draft.guided!,eventBoundary:'blank-line'};
    expect(()=>planAllFamilyAudit(sample,draft,full)).toThrow();
    const oversized='{"action":"allow","secret":"'+'X'.repeat(65536)+'"}';
    expect(()=>planAllFamilyAudit(oversized,draft,preview('{"action":"allow"}',draft))).toThrow();
    const tooMany=Array.from({length:501},(_,i)=>'{"action":"deny","id":'+i+'}').join('\n');
    expect(()=>planAllFamilyAudit(tooMany,createDraft(),
      preview(tooMany.split('\n').slice(0,500).join('\n'),createDraft()))).toThrow();
  });

  it('refuses to report unsupported-only data as an all-family success',()=>{
    const draft=createDraft(),source='a plain message no structure\nanother unrecognized message';
    const full=preview(source,draft);
    expect(()=>planAllFamilyAudit(source,draft,full)).toThrow();
  });

  it('fails closed if a family worker returns fewer/more events, changed source, verified native flags or swapped results',()=>{
    const draft=createDraft();draft.format='json';
    const plan=planAllFamilyAudit(sample,draft,preview(sample,draft));
    const runs=plan.plans.map(p=>preview(p.sample,{...draft,format:p.format}));
    const shortened={...runs[0],events:runs[0].events.slice(1)};
    expect(()=>summarizeAllFamilyAudit(plan,[shortened,runs[1]])).toThrow();
    const manipulated=structuredClone(runs[0]);
    manipulated.events[0].raw='forged event';
    expect(()=>summarizeAllFamilyAudit(plan,[manipulated,runs[1]])).toThrow();
    const claimed={...runs[0],nativeFluentdVerified:true};
    expect(()=>summarizeAllFamilyAudit(plan,[claimed as unknown as typeof runs[0],runs[1]])).toThrow();
    expect(()=>summarizeAllFamilyAudit(plan,[runs[1],runs[0]])).toThrow();
    expect(()=>summarizeAllFamilyAudit(plan,[runs[0]])).toThrow();
  });

  it('supports an exactly accountable recognized mixed input with zero unknown events',()=>{
    const known=sample.split('\n').slice(0,3).join('\n');
    const draft=createDraft();draft.format='json';
    const plan=planAllFamilyAudit(known,draft,preview(known,draft));
    expect(plan.unreviewableEvents).toEqual([]);
    const reports=plan.plans.map(p=>preview(p.sample,{...draft,format:p.format}));
    const report=summarizeAllFamilyAudit(plan,reports);
    expect(report.sourceCount).toBe(3);
    expect(report.unreviewableCount).toBe(0);
    expect(report.reviewedCount).toBe(3);
    expect(report.families).toHaveLength(2);
    expect(report.notSingleParserProof).toBe(true);
  });
});
