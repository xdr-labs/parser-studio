/** Additional frozen independent source transfer beyond the NiFi development holdout. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {arbitrateSourceBody} from '../../src/poc/boundedSourceBodyArbiter';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
import {parseSecurityInput} from '../../src/securityInputPipeline';

const root=path.join(os.homedir(),'.local/state/parserstudio-independent-transfer-20261017');
const sha=(s:Buffer)=>crypto.createHash('sha256').update(s).digest('hex');
const manifest=fs.readFileSync(path.join(root,'sources.pinned.json'));
const summary=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v1.pinned.json'),'utf8'));
const originals=fs.readFileSync(path.join(root,'source-transfer-original-goldens.v1.json'));
if(summary.stage!=='TRANSFER_ORACLE_FROZEN_BEFORE_ANY_CANDIDATE_SCORING'||
   summary.oracle_sha256!=='6944e92d0e5f0f8c4db9fe96a7d05ea0a07a68cb111db2e9bb17c97ddfb2a07b'||
   sha(originals)!==summary.oracle_sha256||
   sha(manifest)!==summary.source_pin_sha256)
  throw Error('Transfer independent upstream assertions or source SHA drifted');
type Golden={name:string;value:string;start_byte:number;end_byte:number};
type Row={id:string;raw:string;raw_sha256:string;raw_bytes:number;fields:Golden[];
  status:string;family:string;publisher:string};
type Actual={name:string;value:unknown;startByte:number;endByte:number};
type Metric={events:number;goldenFields:number;TP:number;FP:number;FN:number;
  exactEvents:number;reviewOnly:number;abstain:number;rawRetained:number;
  invalidControls:number;invalidReviewRisk:number;autoPromoted:number;maxAttempts:number};
const zero=():Metric=>({events:0,goldenFields:0,TP:0,FP:0,FN:0,exactEvents:0,
  reviewOnly:0,abstain:0,rawRetained:0,invalidControls:0,
  invalidReviewRisk:0,autoPromoted:0,maxAttempts:0});
const stages={poc46:zero(),candidate:zero()};
const byCase:Record<string,Record<string,Pick<Metric,'TP'|'FP'|'FN'|'reviewOnly'|'abstain'>>>={};
const rows=JSON.parse(originals.toString('utf8')) as Row[];
if(rows.length!==summary.original_cases||
   rows.filter(x=>x.status==='SCORABLE_SOURCE_ONLY').length!==summary.scorable_originals||
   rows.filter(x=>x.status==='SCORABLE_SOURCE_ONLY').reduce((v,x)=>v+x.fields.length,0)!==summary.field_triples)
  throw Error('Transfer original/golden denominator drifted');
const products={accepted:0,negativeRejected:0,unscorable:0};
for(const row of rows){
  if(sha(Buffer.from(row.raw,'utf8'))!==row.raw_sha256||
     Buffer.byteLength(row.raw,'utf8')!==row.raw_bytes)
    throw Error('Independent transfer original bytes drifted');
  for(const gold of row.fields)
    if(Buffer.from(row.raw,'utf8').subarray(gold.start_byte,gold.end_byte).toString('utf8')!==gold.value)
      throw Error('Original expected UTF8 source byte mismatch');
  if(row.status==='UNSCORABLE'){products.unscorable++;continue;}
  const product=parseSecurityInput(row.raw);
  if(row.status==='NEGATIVE_CONTROL')products.negativeRejected+=Number(!product.ok);
  else products.accepted+=Number(product.ok);
  byCase[row.id]={};
  for(const stage of ['poc46','candidate'] as const){
    const r=stage==='poc46'?arbitrateSourceBody(row.raw):arbitrateIndependentNonJson(row.raw);
    const metric=stages[stage];
    metric.rawRetained+=Number(r.raw===row.raw);
    metric.maxAttempts=Math.max(metric.maxAttempts,r.branchAttempts);
    metric.reviewOnly+=Number(r.disposition.startsWith('REVIEW_ONLY'));
    metric.abstain+=Number(r.disposition==='ABSTAIN_UNSAFE');
    metric.autoPromoted+=Number(r.autoPromoted||r.independentOracleCertified||r.nativeVerified);
    if(row.status==='NEGATIVE_CONTROL'){
      metric.invalidControls++;
      metric.invalidReviewRisk+=Number(r.disposition.startsWith('REVIEW_ONLY'));
      continue;
    }
    metric.events++;
    metric.goldenFields+=row.fields.length;
    const actual:Actual[]=[...r.envelopeFields,...r.bodyClaims];
    let tp=0,fp=0,fn=0;
    for(const gold of row.fields){
      const names=actual.filter(f=>f.name===gold.name);
      const matched=names.find(f=>String(f.value)===gold.value&&
                                  f.startByte===gold.start_byte&&f.endByte===gold.end_byte);
      if(matched)tp++;else {
        fn++;
        fp+=names.length;
      }
      if(matched)fp+=names.filter(f=>f!==matched).length;
    }
    metric.TP+=tp;metric.FP+=fp;metric.FN+=fn;
    metric.exactEvents+=Number(tp===row.fields.length&&fp===0);
    byCase[row.id]![stage]={TP:tp,FP:fp,FN:fn,
      reviewOnly:Number(r.disposition.startsWith('REVIEW_ONLY')),
      abstain:Number(r.disposition==='ABSTAIN_UNSAFE')};
  }
}
const report={status:'QUALIFIED_TRANSFER_SEPARATELY_FROZEN_BEFORE_SCORE',
  sourceSha:sha(manifest),goldenSha:sha(originals),counts:summary.status_counts,
  thirdParty:'apache/metron',scope:'AUTHORED_SOURCE_FIELDS_ONLY',
  pusherRepoOverlap:'none-known-publisher; not production-wires',
  products,byStage:stages,byCase,sourceCompleteSuccess:false,nativeVerified:false};
console.log('INDEPENDENT_TRANSFER '+JSON.stringify(report));
if(stages.candidate.TP<=stages.poc46.TP||stages.candidate.FP>stages.poc46.FP||
   stages.candidate.invalidReviewRisk>stages.poc46.invalidReviewRisk||
   stages.candidate.rawRetained!==4||stages.candidate.autoPromoted||
   stages.candidate.maxAttempts>8)process.exitCode=1;
