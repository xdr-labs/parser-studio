/** Score sealed third-party Go publisher KV expectations without changing originals. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {arbitrateOptionalIndependentCsv} from '../../src/poc/independentQuotedCsvSource';
import {inspectIndependentLogfmt,type LogfmtContext} from '../../src/poc/independentLogfmtSource';

const ROOT=path.join(os.homedir(),'.local/state/parserstudio-independent-logfmt-20261017');
const sha=(data:Buffer)=>crypto.createHash('sha256').update(data).digest('hex');
const manifest=fs.readFileSync(path.join(ROOT,'sources.pinned.json'));
const ref=fs.readFileSync(path.join(ROOT,'independent-expected-fields.v1.json'));
const summary=JSON.parse(fs.readFileSync(path.join(ROOT,'oracle-summary.v1.pinned.json'),'utf8'));
if(summary.stage!=='SEALED_BEFORE_ANY_CANDIDATE_SCORING'||
   summary.oracle_sha256!=='1dc71e3d28513c9f8a46f918c2d8b938406942a18a45e4faca203908283ec4d8'||
   sha(ref)!==summary.oracle_sha256||sha(manifest)!==summary.source_pin_sha256)
  throw Error('Independent publisher logfmt reference not sealed');
type Golden={name:string;ordinal:number;value:string;raw_span:string;
  start_byte:number;end_byte:number};
type Example={id:string;publisher:string;status:string;raw?:string;raw_sha256?:string;
  raw_bytes?:number;field_goldens?:Golden[];
  message_record_framing?:string};
type Claim={name:string;value:unknown;startByte:number;endByte:number};
type Measure={events:number;originalTriples:number;TP:number;FP:number;FN:number;
  exactOnAssertedEvents:number;reviewOnly:number;abstainOrNoClaims:number;
  byteReplayFailures:number;sourceBytesDrift:number;autoPromotion:number;
  branchOver8:number;unscoredExtraCandidates:number;latenciesMs:number[]};
const empty=():Measure=>({events:0,originalTriples:0,TP:0,FP:0,FN:0,
  exactOnAssertedEvents:0,reviewOnly:0,abstainOrNoClaims:0,
  byteReplayFailures:0,sourceBytesDrift:0,autoPromotion:0,branchOver8:0,
  unscoredExtraCandidates:0,latenciesMs:[]});
const stats={preceding:empty(),candidate:empty()};
const byPublisher:Record<string,{preceding:Measure;candidate:Measure}>={};
const distribution:Record<string,number>={};
const rows=JSON.parse(ref.toString('utf8')) as Example[];
if(rows.length!==summary.case_count||
   rows.filter(r=>r.status==='SCORABLE_PARTIAL').length!==summary.scorable_partial_messages||
   rows.filter(r=>r.status==='SCORABLE_PARTIAL').reduce(
     (n,r)=>n+(r.field_goldens?.length??0),0)!==summary.source_name_value_utf8_triples)
  throw Error('Original independent publisher denominator changed');
for(const row of rows){
 if(row.status!=='SCORABLE_PARTIAL')continue;
 if(!row.raw||!row.field_goldens||!row.raw_sha256||!row.raw_bytes)
   throw Error('Scorable third-party original missing');
 const source=Buffer.from(row.raw,'utf8');
 if(source.length!==row.raw_bytes||sha(source)!==row.raw_sha256)
   throw Error('Original publisher bytes no longer match sealed reference');
 for(const golden of row.field_goldens){
   if(source.subarray(golden.start_byte,golden.end_byte).toString('utf8')!==golden.raw_span)
     throw Error('Independently expected original source byte span changed');
 }
 const cohort=byPublisher[row.publisher]??={preceding:empty(),candidate:empty()};
 const context:LogfmtContext={recordFraming:
   row.message_record_framing==='MULTI_RECORD_OR_BOUNDARY_UNQUALIFIED'?
     'CONFIRMED_LOGFMT_BATCH_RECORDS':'CONFIRMED_LOGFMT_SINGLE_RECORD'};
 distribution[context.recordFraming]=(distribution[context.recordFraming]??0)+1;
 const oldStart=performance.now();
 const old=arbitrateOptionalIndependentCsv(row.raw);
 const oldTime=performance.now()-oldStart;
 if(!('bodyClaims' in old))throw Error('Unexpected unsupported source observation');
 const started=performance.now();
 const current=inspectIndependentLogfmt(row.raw,context);
 const candidateTime=performance.now()-started;
 const candidates=[
  {stage:'preceding' as const,observed:[...old.envelopeFields,...old.bodyClaims] as Claim[],
   raw:old.raw,sourceBytes:old.sourceBytes,review:old.disposition.startsWith('REVIEW_ONLY'),
   auto:old.autoPromoted||old.nativeVerified||old.independentOracleCertified,
   branches:old.branchAttempts,milliseconds:oldTime},
  {stage:'candidate' as const,observed:current.claims as Claim[],raw:current.raw,
   sourceBytes:current.sourceBytes,review:current.disposition.startsWith('REVIEW_ONLY'),
   auto:current.autoPromoted||current.nativeVerified||current.independentOracleCertified,
   branches:current.branchAttempts,milliseconds:candidateTime},
 ];
 for(const proposal of candidates){
   for(const to of [stats[proposal.stage],cohort[proposal.stage]]){
     to.events++;
     to.originalTriples+=row.field_goldens.length;
     to.latenciesMs.push(proposal.milliseconds);
     to.reviewOnly+=Number(proposal.review);
     to.abstainOrNoClaims+=Number(proposal.observed.length===0);
     to.sourceBytesDrift+=Number(proposal.raw!==row.raw||proposal.sourceBytes!==source.length);
     to.autoPromotion+=Number(proposal.auto);
     to.branchOver8+=Number(proposal.branches>8);
     let tp=0,fp=0;
     const paired=new Set<number>();
     // Repeated original keys must be matched bijectively by their original
     // name/value/UTF-8 byte triple. A different occurrence is NOT a false
     // positive just because it shares another expected source key name.
     for(const gold of row.field_goldens){
       const at=proposal.observed.findIndex((c,i)=>!paired.has(i)&&
         c.name===gold.name&&c.value===gold.value&&
         c.startByte===gold.start_byte&&c.endByte===gold.end_byte);
       if(at>=0){paired.add(at);tp++;}
     }
     for(let i=0;i<proposal.observed.length;i++){
       if(paired.has(i))continue;
       // Reference is intentionally incomplete. Fields outside the authored
       // expected key scope remain UNSCORABLE rather than fabricated FP.
       if(row.field_goldens.some(g=>g.name===proposal.observed[i]!.name))fp++;
     }
     to.TP+=tp;to.FP+=fp;to.FN+=row.field_goldens.length-tp;
     to.exactOnAssertedEvents+=Number(tp===row.field_goldens.length&&fp===0);
     to.unscoredExtraCandidates+=proposal.observed.filter(c=>
       !row.field_goldens?.some(g=>g.name===c.name)).length;
     for(const claim of proposal.observed){
       const lexical=source.subarray(claim.startByte,claim.endByte).toString('utf8');
       if(proposal.stage==='candidate'&&
          lexical!==current.claims.find(x=>x.startByte===claim.startByte&&
            x.endByte===claim.endByte&&x.name===claim.name)?.rawValueSpan)
         to.byteReplayFailures++;
     }
   }
 }
}
function present(m:Measure){
 const times=[...m.latenciesMs].sort((a,b)=>a-b);
 const {latenciesMs,...metric}=m;
 return {...metric,p95Ms:Number((times[Math.floor((times.length-1)*0.95)]??0).toFixed(3))};
}
const report={
 status:'SEALED_INDEPENDENT_GO_LOGFMT_SOURCE_ONLY_COMPARISON',
 referenceSha:sha(ref),sourceSha:sha(manifest),
 qualifiedOriginals:summary.scorable_partial_messages,expectedTriples:summary.source_name_value_utf8_triples,
 scope:'ONLY upstream-authored original KV name/decoded value/UTF8 byte-span claims',
 byStage:{preceding:present(stats.preceding),candidate:present(stats.candidate)},
 byPublisher:Object.fromEntries(Object.entries(byPublisher).map(
   ([publisher,measure])=>[publisher,{
     preceding:present(measure.preceding),candidate:present(measure.candidate)}])),
 framingCohorts:distribution,
 unscorableOriginalCases:summary.status_counts,
 excludedNilAndBareSourceSlots:summary.missing_or_null_expected_slots_excluded_not_fabricated,
 qualification:'PUBLISHER_TEST_SOURCE_ONLY_NEVER_NATIVE',
 successPromotions:0,
};
console.log('INDEPENDENT_LOGFMT_CANDIDATE '+JSON.stringify(report));
if(stats.candidate.TP<=stats.preceding.TP||
   stats.candidate.FP>stats.preceding.FP||
   stats.candidate.sourceBytesDrift||stats.candidate.byteReplayFailures||
   stats.candidate.autoPromotion||stats.candidate.branchOver8)
 process.exitCode=1;
