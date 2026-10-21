import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planReviewedEventFamilyDraft} from './reviewedEventFamilyDraft';
import {inspectReviewedEventValues} from './reviewedEventValueEvidence';

const badHash='b'.repeat(32);
const raw=[
  {event_type:'threat',sha256:badHash},
  {event_type:'threat',sha256:'a'.repeat(64)},
  {event_type:'user',username:'山田'},
  {event_type:'user',username:'alice'},
].map(item=>JSON.stringify(item)).join('\n');

describe('Stellar 7.0 checked normalization semantics per reviewed event family',()=>{
  it('blocks an official SHA-256 mapping with a source value that is too short',()=>{
    const original={...createDraft(),format:'json' as const,mappings:[]};
    const suite=preview(raw,original);
    const plan=planReviewedEventFamilyDraft(suite,original,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const candidate=plan.candidate;
    const mapping=candidate.eventProfiles!.variants.find(x=>x.name==='threat')!
      .mappings.find(x=>x.source==='sha256')!;
    mapping.target='sha256';mapping.type='string';
    candidate.guided!.groups[mapping.id]='top_fields';
    const result=inspectReviewedEventValues(suite,candidate);
    expect(result.ok).toBe(false);
    if(!result.ok){
      expect(result.reason).toContain('sha256');
      expect(result.reason).toContain('7.0');
      expect(result.reason).not.toContain(badHash);
    }
  });
  it('disallows unsupported official target or type but retains explicitly reviewed vendor-only fields',()=>{
    const original={...createDraft(),format:'json' as const,mappings:[]};
    const suite=preview(raw,original);
    const plan=planReviewedEventFamilyDraft(suite,original,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const draft=plan.candidate;
    const mapping=draft.eventProfiles!.variants.find(x=>x.name==='user')!
      .mappings.find(x=>x.source==='username')!;
    mapping.target='not_official';draft.guided!.groups[mapping.id]='top_fields';
    expect(inspectReviewedEventValues(suite,draft).ok).toBe(false);
    draft.guided!.groups[mapping.id]='vendor_fields';
    expect(inspectReviewedEventValues(suite,draft).ok).toBe(true);
    mapping.target='username';mapping.type='ip';draft.guided!.groups[mapping.id]='top_fields';
    expect(inspectReviewedEventValues(suite,draft).ok).toBe(false);
  });
});
