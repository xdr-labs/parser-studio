/** Read-only independent source-only comparison against pre-frozen publisher claims. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {performance} from 'node:perf_hooks';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {extractGenericStructural} from '../../src/genericStructural';
import {inspectGrammarFunnel} from '../../src/poc/grammarFunnel';
import {arbitrateSourceBody,type SourceFieldClaim} from '../../src/poc/boundedSourceBodyArbiter';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';

type Golden={name:string;value:string;value_type:string;start_byte:number;end_byte:number};
type Original={id:string;family:string;publisher:string;status:string;raw:string|null;
  raw_sha256:string;raw_bytes:number;fields:Golden[];flags:string[]};
type Claim={name:string;value:unknown;startByte?:number;endByte?:number};
type Observation={claims:Claim[];rawPreserved:boolean;review:boolean;abstain:boolean;
  attempts:number;autoPromoted:boolean;hasSpans:boolean};
type Metric={events:number;referenceFields:number;sourceTripleTP:number;sourceTripleFP:number;
  sourceTripleFN:number;fieldValueTP:number;incorrectValues:number;incorrectSpans:number;
  exactSourceGoldens:number;reviewOnly:number;abstentions:number;rawPreserved:number;
  unsafeAutoPromotions:number;unscoredExtraClaims:number;outOfBoundBranches:number;
  negativeControls:number;invalidControlReviewRisk:number;milliseconds:number[]};
const zero=():Metric=>({events:0,referenceFields:0,sourceTripleTP:0,sourceTripleFP:0,
  sourceTripleFN:0,fieldValueTP:0,incorrectValues:0,incorrectSpans:0,
  exactSourceGoldens:0,reviewOnly:0,abstentions:0,rawPreserved:0,unsafeAutoPromotions:0,
  unscoredExtraClaims:0,outOfBoundBranches:0,negativeControls:0,invalidControlReviewRisk:0,
  milliseconds:[]});
const sha=(s:Buffer|string)=>crypto.createHash('sha256').update(s).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-independent-nonjson-20261017');
const sources=fs.readFileSync(path.join(root,'sources.pinned.json'));
const summary=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v2.pinned.json'),'utf8'));
const original=fs.readFileSync(path.join(root,'upstream-authored-original-goldens.v2.json'));
if(summary.stage!=='QUALIFIED_AND_FROZEN_BEFORE_ANY_CANDIDATE_OR_BASELINE_SCORE'||
   summary.qualified_oracle_v2_sha256!=='18c25739376c4bd7289066e147ac73fc5e55344385b0312e7c0e6cab00cea17b'||
   summary.qualified_oracle_v2_sha256!==sha(original)||
   summary.upstream_sources_sha256!==sha(sources))
  throw Error('Non-JSON independently frozen golden or upstream source is not immutable');
const data=JSON.parse(original.toString('utf8')) as Original[];
if(data.length!==summary.original_events||
   data.filter(d=>d.status==='SCORABLE_SOURCE_ONLY').length!==summary.scorable_originals||
   data.reduce((n,d)=>n+(d.status==='SCORABLE_SOURCE_ONLY'?d.fields.length:0),0)!==summary.source_triples)
  throw Error('Precommitted original denominator drifted');

function flatten(v:unknown,out:Claim[],depth=0):void {
  if(depth>6||out.length>2048||!v||typeof v!=='object'||Array.isArray(v))return;
  for(const [key,value] of Object.entries(v)){
    if(value===undefined||key==='source_raw'||key==='raw'||key==='generic')continue;
    if(value&&typeof value==='object'){flatten(value,out,depth+1);continue;}
    if(value!==null)out.push({name:key,value});
  }
}
function product(raw:string):Observation {
  const parsed=parseSecurityInput(raw);
  const claims:Claim[]=[];
  if(parsed.ok)for(const event of parsed.events)flatten(event.fields,claims);
  return {claims,rawPreserved:!parsed.ok||parsed.source_raw===raw,
    review:parsed.ok,abstain:!parsed.ok,attempts:0,autoPromoted:false,hasSpans:false};
}
function structural(raw:string):Observation {
  const result=extractGenericStructural(raw);
  const claims:Claim[]=[];
  if(!result.errors.length)flatten(result.fields,claims);
  return {claims,rawPreserved:true,review:!result.errors.length,
    abstain:result.errors.length>0,attempts:0,autoPromoted:false,hasSpans:false};
}
function observer(raw:string,newLayer:boolean):Observation {
  const result=newLayer?arbitrateIndependentNonJson(raw):arbitrateSourceBody(raw);
  return {claims:[...result.envelopeFields,...result.bodyClaims],
    rawPreserved:result.raw===raw,review:result.disposition.startsWith('REVIEW_ONLY'),
    abstain:result.disposition==='ABSTAIN_UNSAFE',attempts:result.branchAttempts,
    autoPromoted:result.autoPromoted,hasSpans:true};
}
type Stage='unchangedProduct'|'qualifiedStructural'|'poc46'|'independentCandidate';
const stages:Stage[]=['unchangedProduct','qualifiedStructural','poc46','independentCandidate'];
const group:Record<Stage,Record<string,Metric>>={
  unchangedProduct:{},qualifiedStructural:{},poc46:{},independentCandidate:{}
};
const report:Record<Stage,Metric>={
  unchangedProduct:zero(),qualifiedStructural:zero(),poc46:zero(),independentCandidate:zero()
};
const distribution:Record<string,number>={};
let funnelSelection=0,funnelAbstain=0;
function record(row:Original,metric:Metric,result:Observation,timing:number):void {
  metric.milliseconds.push(timing);
  metric.rawPreserved+=Number(result.rawPreserved);
  metric.reviewOnly+=Number(result.review);
  metric.abstentions+=Number(result.abstain);
  metric.unsafeAutoPromotions+=Number(result.autoPromoted);
  metric.outOfBoundBranches+=Number(result.attempts>8);
  if(row.status==='UPSTREAM_INVALID_CONTROL'){
    metric.negativeControls++;
    // Original third-party expected these specific rows to be rejected;
    // lexical review is risk only, not proof of independent false field TP.
    metric.invalidControlReviewRisk+=Number(result.review);
    return;
  }
  if(row.status!=='SCORABLE_SOURCE_ONLY')return;
  metric.events++;
  metric.referenceFields+=row.fields.length;
  const scoped=new Set(row.fields.map(f=>f.name));
  metric.unscoredExtraClaims+=result.claims.filter(c=>!scoped.has(c.name)).length;
  let exact=true;
  for(const truth of row.fields){
    const candidates=result.claims.filter(c=>c.name===truth.name);
    const equivalent=candidates.filter(c=>String(c.value)===truth.value);
    if(equivalent.length)metric.fieldValueTP++;
    else if(candidates.length)metric.incorrectValues++;
    const precise=equivalent.find(c=>c.startByte===truth.start_byte&&
                                   c.endByte===truth.end_byte);
    if(result.hasSpans){
      if(precise)metric.sourceTripleTP++;
      else{
        metric.sourceTripleFN++;
        if(candidates.length)metric.sourceTripleFP+=candidates.length;
        if(equivalent.length)metric.incorrectSpans++;
        exact=false;
      }
      if(precise)metric.sourceTripleFP+=candidates.filter(c=>c!==precise).length;
    }else exact=false;
    if(!precise)exact=false;
  }
  if(exact&&result.hasSpans)metric.exactSourceGoldens++;
}
for(const row of data){
  if(row.raw!==null&&(sha(Buffer.from(row.raw,'utf8'))!==row.raw_sha256||
                        Buffer.byteLength(row.raw,'utf8')!==row.raw_bytes))
    throw Error('A publisher original no longer matches its SHA256 bytes');
  if(row.status==='DUPLICATE_SOURCE_EXCLUDED'||row.status==='UNSCORABLE')continue;
  if(row.raw===null)throw Error('Qualified original absent');
  if(row.status==='SCORABLE_SOURCE_ONLY'){
    for(const field of row.fields){
      if(Buffer.from(row.raw,'utf8').subarray(field.start_byte,field.end_byte).toString('utf8')!==field.value)
        throw Error('Independent golden no longer replays its UTF8 offset');
    }
    distribution[row.family]=(distribution[row.family]??0)+1;
    const g=inspectGrammarFunnel(row.raw);
    funnelSelection+=Number(g.selected!==null);
    funnelAbstain+=Number(g.selected===null);
  }
  for(const stage of stages){
    const start=performance.now();
    const obs=stage==='unchangedProduct'?product(row.raw):
      stage==='qualifiedStructural'?structural(row.raw):
      observer(row.raw,stage==='independentCandidate');
    const delta=performance.now()-start;
    record(row,report[stage],obs,delta);
    const byFamily=group[stage][row.family]??=zero();
    record(row,byFamily,obs,delta);
  }
}
function publicMetric(m:Metric){
  const times=m.milliseconds.slice().sort((a,b)=>a-b);
  const p=(f:number)=>times[Math.min(times.length-1,Math.floor((times.length-1)*f))]??0;
  const {milliseconds,...rest}=m;
  return {...rest,latencyMsP50:Number(p(0.5).toFixed(3)),
    latencyMsP95:Number(p(0.95).toFixed(3)),
    scope:'frozen_author_asserted_claims_only'};
}
const concise=Object.fromEntries(stages.map(k=>[k,publicMetric(report[k])]));
const strata=Object.fromEntries(stages.map(k=>[k,Object.fromEntries(
  Object.entries(group[k]).map(([family,m])=>[family,publicMetric(m)]))]));
const output={
  status:'PRE_FROZEN_INDEPENDENT_ORIGINAL_SOURCE_SCORE',
  sourceSha:sha(sources),oracleSha:sha(original),qualifiedOriginals:summary.scorable_originals,
  sourceTriples:summary.source_triples,excluded:summary.status_counts,
  note:'partial goldens: extra unscored claims are NOT treated as FP nor true positives',
  productAndGenericNoNativeSourceByteSpans:true,
  genericFunnelAdvisory:{scoredSourceTriples:false,selected:funnelSelection,
                         noSelected:funnelAbstain},
  byStage:concise,byFamily:strata,distribution,sourceTypeNotVendorSemantics:true,
  nativeVerified:false};
console.log('INDEPENDENT_NONJSON '+JSON.stringify(output));
const a=report.poc46,b=report.independentCandidate;
if(b.sourceTripleTP<a.sourceTripleTP||
   b.sourceTripleFP>a.sourceTripleFP||
   b.unsafeAutoPromotions||b.outOfBoundBranches||
   b.rawPreserved!==b.events+b.negativeControls||
   a.rawPreserved!==a.events+a.negativeControls)
  process.exitCode=1;
