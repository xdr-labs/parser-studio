import {describe, expect, it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planFamilyIsolation, summarizeIsolatedFamilyPreview} from './familyIsolation';

const source=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"secret":"CUSTOMER_SECRET"}',
  'action=deny src_ip=203.0.113.10 dst_port=22 username=PRIVATE_ID',
  '{"action":"deny","src_ip":"192.0.2.15","dst_port":80,"secret":"SECOND_PRIVATE_VALUE"}',
].join('\n');

describe('one-family independent browser preview for mixed input',()=>{
  it('plans an exact JSON-only worker fixture without changing a mixed raw sample or draft',()=>{
    const draft=createDraft();
    draft.format='json';
    const original=structuredClone(draft);
    const suite=preview(source,draft);
    const plan=planFamilyIsolation(source,draft,suite,'json');
    expect(plan.sample).toContain('CUSTOMER_SECRET');
    expect(plan.sample).toContain('SECOND_PRIVATE_VALUE');
    expect(plan.sample).not.toContain('PRIVATE_ID');
    expect(plan.originalLines).toEqual([1,3]);
    expect(plan.selectedCount).toBe(2);
    expect(plan.sourceCount).toBe(3);
    expect(plan.format).toBe('json');
    expect(draft).toEqual(original);
    expect(source).toContain('PRIVATE_ID');
    const result=preview(plan.sample,{...draft,format:plan.format});
    const report=summarizeIsolatedFamilyPreview(plan,result);
    expect(report).toMatchObject({
      contract:'parser-studio.browser-family-isolation.v0.1',
      format:'json',
      sourceCount:3,selectedCount:2,excludedCount:1,
      nativeFluentdVerified:false,stellarExportVerified:false,
      counts:{total:2,matched:2,extracted:2,normalized:2,failures:0},
    });
    expect(report.perEvent.map(ev=>ev.originalLine)).toEqual([1,3]);
    for(const privateValue of ['CUSTOMER_SECRET','SECOND_PRIVATE_VALUE','PRIVATE_ID','198.51.100.10']){
      expect(JSON.stringify(report)).not.toContain(privateValue);
    }
  });

  it('can review the KV subset without silently changing the authoring format',()=>{
    const draft=createDraft();
    draft.format='json';
    const suite=preview(source,draft);
    const plan=planFamilyIsolation(source,draft,suite,'kv');
    expect(plan.originalLines).toEqual([2]);
    const isolated=preview(plan.sample,{...draft,format:'kv'});
    const report=summarizeIsolatedFamilyPreview(plan,isolated);
    expect(report).toMatchObject({format:'kv',selectedCount:1,excludedCount:2,
      counts:{total:1,matched:1,normalized:1,failures:0}});
    expect(draft.format).toBe('json');
  });

  it('refuses unsupported and absent families, preserving all input for the user',()=>{
    const draft=createDraft();
    const suite=preview(source,draft);
    for(const format of ['unknown','syslog','regex','auto','leef'] as const){
      expect(()=>planFamilyIsolation(source,draft,suite,format)).toThrow();
    }
  });

  it('fails closed on stale preview evidence or unsupported multiline boundary',()=>{
    const draft=createDraft();
    const suite=preview(source,draft);
    expect(()=>planFamilyIsolation(source+'\nextra=1',draft,suite,'json')).toThrow('stale');
    const stale=structuredClone(suite);
    stale.events[0].raw='wrong raw';
    expect(()=>planFamilyIsolation(source,draft,stale,'json')).toThrow('stale');
    draft.guided={...draft.guided!,eventBoundary:'blank-line'};
    expect(()=>planFamilyIsolation(source,draft,suite,'json')).toThrow('single-line');
  });

  it('never hides beyond-limit families or promotes malformed worker response to success',()=>{
    const draft=createDraft();
    const tooMany=Array.from({length:501},(_,i)=>'{"action":"allow","item":'+i+'}').join('\n');
    // Simulate stale/truncated worker preview: planning must reject before losing event 501.
    const first500=preview(Array.from({length:500},(_,i)=>'{"action":"allow","item":'+i+'}').join('\n'),draft);
    expect(()=>planFamilyIsolation(tooMany,draft,first500,'json')).toThrow();
    const suite=preview(source,draft);
    const plan=planFamilyIsolation(source,draft,suite,'json');
    const good=preview(plan.sample,{...draft,format:'json'});
    expect(()=>summarizeIsolatedFamilyPreview(plan,{
      ...good,engine:'browser-preview',nativeFluentdVerified:true,
    } as unknown as typeof good)).toThrow('verification');
    expect(()=>summarizeIsolatedFamilyPreview(plan,{
      ...good,events:good.events.slice(1),
    })).toThrow('event');
  });

  it('never exposes arbitrary worker diagnostic code or messages in a family report',()=>{
    const draft=createDraft();draft.format='json';
    const suite=preview(source,draft);
    const plan=planFamilyIsolation(source,draft,suite,'json');
    const result=preview(plan.sample,{...draft,format:'json'});
    result.events[0].diagnostics.push({stage:'validate',severity:'warning',
      code:'PRIVATE_USER_ACCOUNT',message:'secret-event-raw-message'});
    const summary=summarizeIsolatedFamilyPreview(plan,result);
    expect(summary.perEvent[0].diagnosticCodes).toContain('DIAGNOSTIC_UNAVAILABLE');
    expect(JSON.stringify(summary)).not.toContain('PRIVATE_USER_ACCOUNT');
    expect(JSON.stringify(summary)).not.toContain('secret-event-raw-message');
  });

  it('includes all per-event failure codes without copying the original source values',()=>{
    const draft=createDraft();
    draft.format='json';
    draft.mappings[0].source='missing_field';
    const sourceWithInvalid='{"action":"deny","src_ip":"invalid-ip","dst_port":65536,"secret":"CUSTOMER_SECRET"}';
    const suite=preview(sourceWithInvalid,draft);
    const plan=planFamilyIsolation(sourceWithInvalid,draft,suite,'json');
    const result=preview(plan.sample,{...draft,format:'json'});
    const summary=summarizeIsolatedFamilyPreview(plan,result);
    expect(summary.counts.failures).toBe(1);
    expect(summary.perEvent[0].diagnosticCodes.length).toBeGreaterThan(0);
    expect(JSON.stringify(summary)).not.toContain('CUSTOMER_SECRET');
    expect(JSON.stringify(summary)).not.toContain('invalid-ip');
  });
});
