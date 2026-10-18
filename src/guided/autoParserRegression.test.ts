import {describe,it,expect} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {assessHoldoutIndependence,compareBrowserSuites,compareCandidate,compareMappingCorrectionCandidate,proposeReviewableMapping} from './autoParserRegression';

const train=[
 '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"user":"PRIVATE_A"}',
 '{"action":"deny","src_ip":"203.0.113.5","dst_port":22,"user":"PRIVATE_B"}',
].join('\n');
const holdout=[
 '{"action":"allow","src_ip":"192.0.2.17","dst_port":8080,"user":"PRIVATE_HOLDOUT"}',
 '{"action":"deny","src_ip":"192.0.2.18","dst_port":52,"user":"PRIVATE_HOLDOUT_TWO"}',
].join('\n');
const fixture=():ParserDraft=>({...createDraft(),format:'json'});
const compare=(source=train,draft=fixture())=>{
 const base=preview(source,draft);
 const proposal=proposeReviewableMapping(source,draft,base);
 if(!proposal.ok)throw new Error('No reviewable candidate');
 return {draft,base,proposal,output:compareCandidate({source,baseline:base,
   candidate:preview(source,proposal.candidate),holdout:{source:holdout,
     baseline:preview(holdout,draft),candidate:preview(holdout,proposal.candidate)}})};
};

describe('P0-AP4 exact source, full coverage and holdout candidate regression',()=>{
 it('proposes only one explicit safe field rule without changing the accepted rules',()=>{
   const draft=fixture(),old=structuredClone(draft);
   const base=preview(train,draft);
   const p=proposeReviewableMapping(train,draft,base);
   expect(p).toMatchObject({ok:true,approvalRequired:true,mapping:{source:'user',target:'user'}});
   if(!p.ok)return;
   expect(draft).toEqual(old);
   expect(p.candidate.mappings).toHaveLength(draft.mappings.length+1);
   expect(p.candidate.guided?.receiver.port).toBe(draft.guided?.receiver.port);
   expect(JSON.stringify(p.candidate)).not.toContain('PRIVATE_A');
 });
 it('compares both training and independent held-out values without returning source values',()=>{
   const result=compare();
   expect(result.output.acceptedWithoutRegression).toBe(true);
   expect(result.output.holdoutStatus).toBe('TESTED');
   expect(result.output.baseline).toMatchObject({
     contract:'auto-parser.regression.v0.1',sourceCount:2,accounted:2,
     positiveBefore:0,positiveAfter:2,regressions:0,
     nativeVerified:false,targetVerified:false,browserOnly:true,
   });
   expect(result.output.baseline.fieldAdditions).toBeGreaterThan(0);
   expect(result.output.holdout?.sourceCount).toBe(2);
   expect(result.output.holdout?.regressions).toBe(0);
   for(const sensitive of ['PRIVATE_A','PRIVATE_B','PRIVATE_HOLDOUT','198.51.100.10','192.0.2.17'])
     expect(JSON.stringify(result.output)).not.toContain(sensitive);
 });
 it('retains all four mixed/unknown event families instead of silently skipping input',()=>{
   const draft=fixture();
   const mixed=train+'\nunknown PRIVATE_LOG_CONTENT\n<34>Oct 12 13:14:15 fw app: action=deny';
   const base=preview(mixed,draft);
   const report=compareBrowserSuites(mixed,base,base);
   expect(report.sourceCount).toBe(4);
   expect(report.accounted).toBe(4);
   expect(report.families.reduce((n,f)=>n+f.count,0)).toBe(4);
   expect(report.events.length).toBe(4);
   expect(report.events[2]?.reason).toBe('SOURCE_INVALID');
   expect(report.events[3]?.reason).toBe('COMPILER_UNSUPPORTED');
   expect(JSON.stringify(report)).not.toContain('PRIVATE_LOG_CONTENT');
 });
 it('labels a missing holdout explicitly, never as independently tested',()=>{
   const draft=fixture(),baseline=preview(train,draft);
   const result=compareCandidate({source:train,baseline,candidate:baseline});
   expect(result.holdout).toBeNull();
   expect(result.holdoutStatus).toBe('NOT_SUPPLIED');
   expect(result.holdoutIndependence).toBeNull();
   expect(result.approvalRequired).toBe(true);
 });
 it('rejects identical, overlapping and undersized holdouts before candidate approval',()=>{
   expect(assessHoldoutIndependence(train,train)).toMatchObject({ok:false,reason:'IDENTICAL_TO_TRAINING'});
   expect(assessHoldoutIndependence(train,train.split('\n')[0]+'\n'+holdout.split('\n')[0]))
     .toMatchObject({ok:false,reason:'TRAINING_OVERLAP',overlapCount:1});
   expect(assessHoldoutIndependence(train,holdout.split('\n')[0]!))
     .toMatchObject({ok:false,reason:'TOO_SMALL',holdoutUnique:1,requiredUnique:2});
   expect(assessHoldoutIndependence(train,holdout)).toMatchObject({ok:true,holdoutUnique:2,requiredUnique:2});
   const draft=fixture(),baseline=preview(train,draft);
   const rejected=compareCandidate({source:train,baseline,candidate:baseline,
     holdout:{source:train,baseline:preview(train,draft),candidate:preview(train,draft)}});
   expect(rejected).toMatchObject({holdout:null,holdoutStatus:'REJECTED',acceptedWithoutRegression:false,
     holdoutIndependence:{ok:false,reason:'IDENTICAL_TO_TRAINING'}});
 });
 it('permits exactly one explicitly scoped mapping replacement while protecting every unrelated field',()=>{
   const draft=fixture(),corrected=structuredClone(draft);
   corrected.mappings[0]={...corrected.mappings[0]!,target:'custom.source_address'};
   const generic=compareCandidate({source:train,baseline:preview(train,draft),candidate:preview(train,corrected),
     holdout:{source:holdout,baseline:preview(holdout,draft),candidate:preview(holdout,corrected)}});
   expect(generic.acceptedWithoutRegression).toBe(false);
   const scoped=compareMappingCorrectionCandidate({source:train,baseline:preview(train,draft),candidate:preview(train,corrected),
     holdout:{source:holdout,baseline:preview(holdout,draft),candidate:preview(holdout,corrected)}},
     {oldTarget:'custom.source_ip',newTarget:'custom.source_address'});
   expect(scoped).toMatchObject({acceptedWithoutRegression:true,holdoutStatus:'TESTED',
     baseline:{regressions:0,fieldRemovals:0,typeChanges:0},holdout:{regressions:0,fieldRemovals:0,typeChanges:0}});
   const damaged=structuredClone(corrected);damaged.mappings[1]={...damaged.mappings[1]!,source:'missing_field'};
   const blocked=compareMappingCorrectionCandidate({source:train,baseline:preview(train,draft),candidate:preview(train,damaged)},
     {oldTarget:'custom.source_ip',newTarget:'custom.source_address'});
   expect(blocked.acceptedWithoutRegression).toBe(false);
   expect(blocked.baseline.fieldRemovals).toBeGreaterThan(0);
 });
 it('detects a newly broken known-good mapping and disallows approval',()=>{
   const draft=fixture(),broken=fixture();
   const stable=train.split('\n').map(s=>{
     const {user,...other}=JSON.parse(s) as Record<string,unknown>;
     return JSON.stringify(other);
   }).join('\n');
   broken.mappings[0]={...broken.mappings[0]!,source:'missing_field'};
   const output=compareCandidate({source:stable,baseline:preview(stable,draft),
     candidate:preview(stable,broken)});
   expect(output.acceptedWithoutRegression).toBe(false);
   expect(output.baseline.regressions).toBeGreaterThan(0);
 });
 it('fails closed on truncated, reordered or stale current/holdout preview',()=>{
   const draft=fixture(),suite=preview(train,draft);
   const swap=structuredClone(suite);swap.events.reverse();
   expect(()=>compareBrowserSuites(train,suite,swap)).toThrow();
   expect(()=>compareBrowserSuites(train+'\nnew event',suite,suite)).toThrow();
   const tampered=structuredClone(suite);tampered.counts.total=999;
   expect(()=>compareBrowserSuites(train,suite,tampered)).toThrow();
   const forged=structuredClone(suite);forged.nativeFluentdVerified=true as false;
   expect(()=>compareBrowserSuites(train,suite,forged)).toThrow();
   const fabricated=structuredClone(suite);fabricated.counts.failures=2;
   expect(()=>compareBrowserSuites(train,suite,fabricated)).toThrow();
 });
 it('rejects unsupported, single-event and already complete samples for safe repair',()=>{
   const draft=fixture();
   expect(proposeReviewableMapping(train.split('\n')[0]!,draft,preview(train.split('\n')[0]!,draft)))
     .toMatchObject({ok:false,reason:'INSUFFICIENT_SAMPLE'});
   const minimal=train.split('\n').map(s=>{
     const {user,...other}=JSON.parse(s) as Record<string,unknown>;
     return JSON.stringify(other);
   }).join('\n');
   expect(proposeReviewableMapping(minimal,draft,preview(minimal,draft)))
     .toMatchObject({ok:false,reason:'NO_SAFE_CHANGE'});
 });
});
