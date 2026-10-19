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
 it('fails closed instead of silently truncating a wide event or multi-sample field union',()=>{
   const draft={...createDraft(),format:'json' as const};
   const wide=Object.fromEntries(Array.from({length:101},(_,index)=>
     ['wide_'+index,'v']));
   const source=[
     JSON.stringify({event_type:'threat',...wide}),
     JSON.stringify({event_type:'user',username:'demo'}),
   ].join('\n');
   const tooWide=planReviewedEventFamilyDraft(preview(source,draft),draft,'event_type');
   expect(tooWide.ok).toBe(false);
   if(!tooWide.ok)expect(tooWide.reason).toMatch(/100.*field/);
   const first=Object.fromEntries(Array.from({length:70},(_,index)=>
     ['first_'+index,'v']));
   const second=Object.fromEntries(Array.from({length:70},(_,index)=>
     ['second_'+index,'v']));
   const mixed=[
     JSON.stringify({event_type:'threat',...first}),
     JSON.stringify({event_type:'threat',...second}),
     JSON.stringify({event_type:'user',username:'demo'}),
   ].join('\n');
   const union=planReviewedEventFamilyDraft(preview(mixed,draft),draft,'event_type');
   expect(union.ok).toBe(false);
   if(!union.ok)expect(union.reason).toMatch(/100.*field/);
 });
 it('rejects colliding reviewed output paths before saving a draft, but permits exclusive variants',()=>{
   const draft={...createDraft(),format:'json' as const};
   const plan=planReviewedEventFamilyDraft(preview(dataset,draft),draft,'event_type');
   expect(plan.ok).toBe(true);
   if(!plan.ok)return;
   const candidate=structuredClone(plan.candidate);
   const threat=candidate.eventProfiles!.variants.find(x=>x.name==='threat')!;
   const user=candidate.eventProfiles!.variants.find(x=>x.name==='user')!;
   threat.mappings[0]!.target='custom.reused';
   user.mappings[0]!.target='custom.reused';
   expect(toBackendProject(candidate).ok).toBe(true);
   // Two fields within the same branch cannot write one output.
   candidate.guided!.groups.extra=candidate.guided!.groups[threat.mappings[0]!.id]??'vendor_fields';
   threat.mappings.push({...threat.mappings[0]!,id:'extra',source:'extra_field',
     target:'custom.reused.deep'});
   const duplicated=toBackendProject(candidate);
   expect(duplicated.ok).toBe(false);
   if(!duplicated.ok)expect(duplicated.issues.some(x=>x.code==='EVENT_OUTPUT_COLLISION')).toBe(true);
   threat.mappings.pop();
   candidate.mappings=[{id:'shared',source:'event_type',target:'custom.reused',type:'string'}];
   candidate.guided!.groups.shared=candidate.guided!.groups[threat.mappings[0]!.id]??'vendor_fields';
   const sharedCollision=toBackendProject(candidate);
   expect(sharedCollision.ok).toBe(false);
   if(!sharedCollision.ok)expect(sharedCollision.issues.some(x=>x.code==='EVENT_OUTPUT_COLLISION')).toBe(true);
 });

});
