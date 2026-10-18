import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planReviewedEventFamilyDraft} from './reviewedEventFamilyDraft';
import {toBackendProject} from './backendAdapter';
import {validateEventProfiles} from './multiEventRouting';

const dataset=[
  '{"event_type":"threat","src_ip":"192.0.2.1","action":"deny"}',
  '{"event_type":"user","username":"김민수","action":"allow"}',
  '{"event_type":"asset","hostname":"fw01","action":"allow"}',
].join('\n');

describe('Reviewed conditional event families are explicit source contracts',()=>{
 it('builds one candidate without altering original mappings or multilingual data',()=>{
   const draft={...createDraft(),format:'json' as const};
   const before=structuredClone(draft);
   const suite=preview(dataset,draft);
   const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
   expect(plan.ok).toBe(true);
   if(!plan.ok)return;
   expect(draft).toEqual(before);
   expect(plan.types.map(item=>item.name)).toEqual(['threat','user','asset']);
   expect(plan.candidate.eventProfiles?.variants).toHaveLength(3);
   expect(validateEventProfiles(plan.candidate.eventProfiles)).toBe(null);
   expect(plan.candidate.guided?.classification.rules.every(rule=>
      plan.candidate.mappings.some(mapping=>mapping.source===rule.sourceField))).toBe(true);
   const backend=toBackendProject(plan.candidate);
   expect(backend.ok).toBe(true);
   if(!backend.ok)return;
   expect(backend.project.normalization.eventProfiles?.unknown).toBe('reject');
   expect(backend.project.normalization.eventProfiles?.variants).toHaveLength(3);
   const json=JSON.stringify(backend.project);
   expect(json).not.toContain('김민수');
   expect(json).not.toContain('192.0.2.1');
 });
 it('requires explicit unique types and disallows unparsed or ambiguous sample',()=>{
   const draft={...createDraft(),format:'json' as const};
   const same=preview([
    '{"event_type":"threat","action":"deny"}',
    '{"event_type":"threat","action":"allow"}',
   ].join('\n'),draft);
   expect(planReviewedEventFamilyDraft(same,draft,'event_type').ok).toBe(false);
   const bad=preview(dataset,draft);
   expect(planReviewedEventFamilyDraft(bad,draft,'__proto__').ok).toBe(false);
   expect(planReviewedEventFamilyDraft(bad,{...draft,format:'auto'},'event_type').ok).toBe(false);
 });
});
