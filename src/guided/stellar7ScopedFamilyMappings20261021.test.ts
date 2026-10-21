import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planReviewedEventFamilyDraft} from './reviewedEventFamilyDraft';
import {proposeStellar7FamilyMappings,applyStellar7FamilyMapping} from './stellar7ScopedFamilyMappings';
import {toBackendProject} from './backendAdapter';
import {inspectReviewedEventValues} from './reviewedEventValueEvidence';

const threatHash='a'.repeat(64);
const raw=[
  {event_type:'threat',src_ip:'192.0.2.11',action:'deny',sha256:threatHash,request_status:403},
  {event_type:'threat',src_ip:'192.0.2.12',action:'block',sha256:threatHash,request_status:404},
  {event_type:'user',username:'김민수',login_result:'failure',host:{ip:'198.51.100.5'}},
  {event_type:'user',username:'山田',login_result:'success',host:{ip:'198.51.100.6'}},
  {event_type:'asset',host:{name:'asset-01'},process:{name:'agent.exe'}},
  {event_type:'asset',host:{name:'asset-02'},process:{name:'agent2.exe'}},
].map(record=>JSON.stringify(record)).join('\n');
const base=()=>({...createDraft(),format:'json' as const,mappings:[]});

describe('fixed Stellar 7.0 evidence is scoped to explicitly reviewed event-family routes',()=>{
  it('suggests only type-compatible, whole-family mappings without leaking synthetic field values',()=>{
    const draft=base(),suite=preview(raw,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    expect(plan.ok).toBe(true);
    if(!plan.ok)return;
    const candidates=proposeStellar7FamilyMappings(suite,plan.candidate);
    expect(candidates).toContainEqual(expect.objectContaining({
      family:'threat',source:'src_ip',target:'srcip',confidence:'HIGH',
      total:2,observed:2,group:'top_fields',catalogRelease:'7.0.xs',
    }));
    expect(candidates).toContainEqual(expect.objectContaining({
      family:'user',source:'username',target:'username',confidence:'HIGH',
    }));
    expect(candidates).toContainEqual(expect.objectContaining({
      family:'asset',source:'host.name',target:'host.name',
      group:'ns_fields',confidence:'HIGH',
    }));
    expect(candidates.some(candidate=>candidate.source==='request_status')).toBe(false);
    expect(JSON.stringify(candidates)).not.toContain('김민수');
    expect(JSON.stringify(candidates)).not.toContain('192.0.2.11');
    expect(draft.eventProfiles).toBeUndefined();
  });

  it('applies only reviewed high-confidence per-family destinations, preserving conditional isolation and source',()=>{
    const draft=base(),suite=preview(raw,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const original=structuredClone(plan.candidate),originalRaw=suite.events.map(e=>e.raw);
    let reviewed=plan.candidate;
    const proposals=proposeStellar7FamilyMappings(suite,reviewed);
    const allow=[
      ['threat','src_ip'],['threat','action'],['threat','sha256'],
      ['user','username'],['user','login_result'],['user','host.ip'],
      ['asset','host.name'],['asset','process.name'],
    ];
    for(const [family,source] of allow){
      const suggestion=proposals.find(item=>item.family===family&&item.source===source);
      if(!suggestion)throw Error('Missing reviewed 7.0 suggestion '+family+':'+source);
      expect(suggestion.confidence).toBe('HIGH');
      const applied=applyStellar7FamilyMapping(reviewed,suggestion,suite);
      expect(applied.ok).toBe(true);
      if(applied.ok)reviewed=applied.draft;
    }
    expect(toBackendProject(reviewed).ok).toBe(true);
    expect(inspectReviewedEventValues(suite,reviewed)).toMatchObject({ok:true});
    const compiled=toBackendProject(reviewed);
    if(!compiled.ok)throw Error(JSON.stringify(compiled.issues));
    const vars=compiled.project.normalization.eventProfiles?.variants??[];
    expect(vars.find(v=>v.name==='threat')?.topFields.src_ip)
      .toMatchObject({normalized_name:'srcip',data_type:'ip'});
    expect(vars.find(v=>v.name==='user')?.nsFields['host.ip'])
      .toMatchObject({normalized_name:'host.ip',data_type:'ip'});
    expect(vars.find(v=>v.name==='asset')?.nsFields['process.name'])
      .toMatchObject({normalized_name:'process.name',data_type:'string'});
    const result=preview(raw,reviewed);
    const goldens=[
      {srcip:'192.0.2.11',action:'deny',sha256:threatHash},
      {srcip:'192.0.2.12',action:'block',sha256:threatHash},
      {username:'김민수',login_result:'failure',host:{ip:'198.51.100.5'}},
      {username:'山田',login_result:'success',host:{ip:'198.51.100.6'}},
      {host:{name:'asset-01'},process:{name:'agent.exe'}},
      {host:{name:'asset-02'},process:{name:'agent2.exe'}},
    ];
    let matchedOfficialFields=0;
    for(const [i,expected] of goldens.entries()){
      expect(result.events[i]?.normalized).toMatchObject(expected);
      for(const [target,expectedValue] of Object.entries(expected)){
        expect(result.events[i]?.normalized[target]).toEqual(expectedValue);
        matchedOfficialFields++;
      }
    }
    // Six manually-authored synthetic event goldens, 16 exact value matches.
    // This is fixture coverage, not independent manufacturer accuracy.
    expect(matchedOfficialFields).toBe(16);
    expect(result.events.map(e=>e.raw)).toEqual(originalRaw);
    expect(plan.candidate).toEqual(original);
    expect(reviewed.eventProfiles?.unknown).toBe('reject');
  });

  it('never upgrades ambiguous, incomplete or invalid evidence within a single family',()=>{
    const records=[
      {event_type:'threat',src_ip:'192.0.2.7',source_ip:'192.0.2.8',sha256:'a'.repeat(32)},
      {event_type:'threat',src_ip:'192.0.2.9',source_ip:'192.0.2.10'},
      {event_type:'user',username:'alice',action:'login'},
      {event_type:'user',username:'bob',action:'logout'},
    ];
    const draft=base(),suite=preview(records.map(record=>JSON.stringify(record)).join('\n'),draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const candidates=proposeStellar7FamilyMappings(suite,plan.candidate);
    for(const source of ['src_ip','source_ip']){
      const ambiguous=candidates.find(c=>c.family==='threat'&&c.source===source);
      expect(ambiguous).toMatchObject({confidence:'REVIEW',safeForBulk:false});
      expect(applyStellar7FamilyMapping(plan.candidate,ambiguous!,suite)).toMatchObject({ok:false});
    }
    const hash=candidates.find(c=>c.family==='threat'&&c.source==='sha256');
    expect(hash).toMatchObject({confidence:'REVIEW',safeForBulk:false,total:2,observed:1});
    expect(candidates.some(c=>c.family==='threat'&&c.confidence==='HIGH'&&c.target==='srcip')).toBe(false);
    expect(candidates.find(c=>c.family==='user'&&c.source==='username')).toMatchObject({confidence:'HIGH'});
  });

  it('refuses stale/forged evidence and never overwrites a manually reviewed mapping',()=>{
    const draft=base(),suite=preview(raw,draft);
    const plan=planReviewedEventFamilyDraft(suite,draft,'event_type');
    if(!plan.ok)throw Error(plan.reason);
    const candidate=proposeStellar7FamilyMappings(suite,plan.candidate)
      .find(item=>item.family==='threat'&&item.source==='src_ip');
    if(!candidate)throw Error('Missing initial 7.0 source-backed candidate');
    expect(candidate).toMatchObject({confidence:'HIGH',safeForBulk:true});
    expect(applyStellar7FamilyMapping(plan.candidate,candidate,undefined))
      .toMatchObject({ok:false});
    expect(applyStellar7FamilyMapping(plan.candidate,{
      ...candidate,target:'dstip',
    },suite)).toMatchObject({ok:false});
    const changed=preview(raw.replace('192.0.2.11','invalid-ip'),draft);
    expect(applyStellar7FamilyMapping(plan.candidate,candidate,changed))
      .toMatchObject({ok:false});
    const manual=structuredClone(plan.candidate);
    const threat=manual.eventProfiles!.variants.find(item=>item.name==='threat')!;
    const selected=threat.mappings.find(item=>item.source==='src_ip')!;
    selected.target='custom.manual_author_choice';
    expect(proposeStellar7FamilyMappings(suite,manual).some(item=>
      item.family==='threat'&&item.source==='src_ip')).toBe(false);
    expect(applyStellar7FamilyMapping(manual,candidate,suite))
      .toMatchObject({ok:false});
    expect(selected.target).toBe('custom.manual_author_choice');
  });

});
