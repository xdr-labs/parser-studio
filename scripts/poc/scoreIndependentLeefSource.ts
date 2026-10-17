/** Compare the unchanged stacked baseline and a NEW source-only LEEF observer. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {performance} from 'node:perf_hooks';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
import {arbitrateIndependentLeef} from '../../src/poc/independentLeefSource';
const root=path.join(os.homedir(),'.local/state/parserstudio-independent-leef-20261017');
const sha=(x:Buffer)=>crypto.createHash('sha256').update(x).digest('hex');
const sources=fs.readFileSync(path.join(root,'sources.pinned.json'));
const pinned=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v1.pinned.json'),'utf8'));
const original=fs.readFileSync(path.join(root,'leef-upstream-original-goldens.v1.json'));
if(pinned.stage!=='INDEPENDENT_EXPECTED_GOLDENS_FROZEN_BEFORE_BASELINE_OR_CANDIDATE_SCORING'||
   pinned.oracle_sha256!=='7c66600785630316ec29ae936048a78119def5060cceadb4276aa9cecbf41aff'||
   sha(original)!==pinned.oracle_sha256||sha(sources)!==pinned.source_pin_sha256)
  throw Error('Independent pinned LEEF source/goldens are not immutable');
type Field={name:string;value:string;start_byte:number;end_byte:number};
type Row={id:string;source:string;raw:string;raw_sha256:string;raw_bytes:number;
  fields:Field[];status:string};
type Stat={events:number;triples:number;tp:number;fp:number;fn:number;exactEvents:number;
  review:number;abstain:number;invalidControls:number;invalidReviewRisk:number;
  unscoredExtraClaims:number;rawRetained:number;autoPromotion:number;
  branchBoundFailures:number;utf8SourceReplayFailures:number;millis:number[]};
const blank=():Stat=>({events:0,triples:0,tp:0,fp:0,fn:0,exactEvents:0,
  review:0,abstain:0,invalidControls:0,invalidReviewRisk:0,
  unscoredExtraClaims:0,rawRetained:0,autoPromotion:0,
  branchBoundFailures:0,utf8SourceReplayFailures:0,millis:[]});
const totals={poc47:blank(),leefCandidate:blank()};
const byPublisher:Record<string,{poc47:Stat;leefCandidate:Stat}>={};
let productPreviewOk=0;
const rows=JSON.parse(original.toString('utf8')) as Row[];
if(rows.length!==pinned.originals||
   rows.filter(r=>r.status==='SCORABLE_SOURCE_ONLY').length!==pinned.scorable_events||
   rows.filter(r=>r.status==='SCORABLE_SOURCE_ONLY').reduce((sum,r)=>sum+r.fields.length,0)!==
   pinned.source_triples)
  throw Error('Independent original LEEF denominators drifted');
for(const row of rows){
  const encoded=Buffer.from(row.raw,'utf8');
  if(sha(encoded)!==row.raw_sha256||encoded.length!==row.raw_bytes)
    throw Error('Publisher raw LEEF byte SHA drift');
  if(row.status==='SCORABLE_SOURCE_ONLY')
    productPreviewOk+=Number(parseSecurityInput(row.raw).ok);
  const group=byPublisher[row.source]??={poc47:blank(),leefCandidate:blank()};
  for(const stage of ['poc47','leefCandidate'] as const){
    const t=performance.now();
    const result=stage==='poc47'?
      arbitrateIndependentNonJson(row.raw):arbitrateIndependentLeef(row.raw);
    const elapsed=performance.now()-t;
    for(const stat of [totals[stage],group[stage]]){
      stat.millis.push(elapsed);
      stat.rawRetained+=Number(result.raw===row.raw&&result.sourceBytes===encoded.length);
      stat.autoPromotion+=Number(result.autoPromoted||result.independentOracleCertified||result.nativeVerified);
      stat.branchBoundFailures+=Number(result.branchAttempts>8);
      const review=result.disposition.startsWith('REVIEW_ONLY');
      stat.review+=Number(review);
      stat.abstain+=Number(result.disposition==='ABSTAIN_UNSAFE');
      if(row.status==='UPSTREAM_INVALID_CONTROL'){
        stat.invalidControls++;
        stat.invalidReviewRisk+=Number(review);
        continue;
      }
      const actual=[...result.envelopeFields,...result.bodyClaims];
      stat.events++;
      stat.triples+=row.fields.length;
      stat.unscoredExtraClaims+=actual.filter(c=>!row.fields.some(g=>g.name===c.name)).length;
      let tp=0,fp=0;
      for(const gold of row.fields){
        const byName=actual.filter(c=>c.name===gold.name);
        const winner=byName.find(c=>String(c.value)===gold.value&&
          c.startByte===gold.start_byte&&c.endByte===gold.end_byte);
        if(winner){tp++;fp+=byName.filter(c=>c!==winner).length;}
        else fp+=byName.length;
      }
      stat.tp+=tp;stat.fp+=fp;stat.fn+=row.fields.length-tp;
      stat.exactEvents+=Number(tp===row.fields.length&&fp===0);
    }
    for(const field of [...result.envelopeFields,...result.bodyClaims]){
      if(encoded.subarray(field.startByte,field.endByte).toString('utf8')!==field.rawSpanValue){
        totals[stage].utf8SourceReplayFailures++;
        group[stage].utf8SourceReplayFailures++;
      }
    }
  }
}
const publicStat=(s:Stat)=>{
  const ordered=[...s.millis].sort((a,b)=>a-b);
  const p95=ordered[Math.floor((ordered.length-1)*0.95)]??0;
  const {millis,...rest}=s;
  return {...rest,latencyP95Ms:Number(p95.toFixed(3))};
};
const report={status:'FROZEN_NEW_INDEPENDENT_LEEF_ORIGINAL_SCORE',
  originalSha:sha(original),sourceSha:sha(sources),
  scorableOriginals:pinned.scorable_events,sourceTriples:pinned.source_triples,
  invalidControls:pinned.negative_controls,productPreviewOk,
  byStage:{poc47:publicStat(totals.poc47),candidate:publicStat(totals.leefCandidate)},
  byPublisher:Object.fromEntries(Object.entries(byPublisher).map(([k,v])=>[k,
    {poc47:publicStat(v.poc47),candidate:publicStat(v.leefCandidate)}])),
  notes:'source-only partial publisher assertions; unscored fields are not TP; no native verification'};
console.log('INDEPENDENT_LEEF '+JSON.stringify(report));
const b=totals.poc47,n=totals.leefCandidate;
if(n.tp<=b.tp||n.fp>b.fp||n.invalidReviewRisk>b.invalidReviewRisk||
   n.rawRetained!==pinned.originals||n.branchBoundFailures||n.autoPromotion||
   n.utf8SourceReplayFailures)
  process.exitCode=1;
