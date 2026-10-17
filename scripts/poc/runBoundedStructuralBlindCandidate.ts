/** Byte-exact independent oracle scorer. Prints counters and SHA only. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectBoundedSourceSpans} from '../../src/poc/boundedStructuralSourceSpans';

type RefField={path:string;value:unknown;type:string;value_start_byte:number;value_end_byte:number};
type RefRow={id:string;family:string;split:string;raw:string|null;raw_event_sha256:string;
  fields:RefField[];oracle_status:string};
type Scored={all:number;scorable:number;excluded:number;referenceFields:number;
  reviewCandidates:number;reviewNoOracle:number;abstentionScorable:number;
  tp:number;fp:number;fn:number;exactEvents:number;wrongValue:number;
  wrongByteOffset:number;rawIdentityMatches:number;autoPromotions:number;
  unsafeReviewGate:number;rawOnly:number;jsonCandidate:number;syslogJsonCandidate:number};
const blank=():Scored=>({all:0,scorable:0,excluded:0,referenceFields:0,reviewCandidates:0,
  reviewNoOracle:0,abstentionScorable:0,tp:0,fp:0,fn:0,exactEvents:0,
  wrongValue:0,wrongByteOffset:0,rawIdentityMatches:0,autoPromotions:0,
  unsafeReviewGate:0,rawOnly:0,jsonCandidate:0,syslogJsonCandidate:0});
const add=(to:Scored,from:Scored)=>{for(const key of Object.keys(to) as (keyof Scored)[])to[key]+=from[key];};
const sha=(v:string|Buffer)=>crypto.createHash('sha256').update(v).digest('hex');
const dir=path.join(os.homedir(),'.local/state/parserstudio-generalization-blind-20261017');
const mode=process.argv[2]??'development';
if(mode!=='development'&&mode!=='sealed_holdout')throw Error('Invalid cohort selection');
const frozen=JSON.parse(fs.readFileSync(path.join(dir,'oracle-summary.pinned.json'),'utf8'));
const recordsBuffer=fs.readFileSync(path.join(dir,'frozen-records-and-oracle.json'));
if(sha(recordsBuffer)!==frozen.private_oracle_sha256)
  throw Error('Private independent oracle changed');
const pinned=fs.readFileSync(path.join(dir,'sources.pinned.json'));
if(sha(pinned)!==frozen.source_manifest_sha256)throw Error('Source provenance changed');
const candidates=JSON.parse(recordsBuffer.toString('utf8')) as RefRow[];
if(candidates.length!==frozen.all_events)throw Error('Unfrozen denominator');
const candidatePath=path.resolve(__dirname,'../../src/poc/boundedStructuralSourceSpans.ts');
const candidateHash=sha(fs.readFileSync(candidatePath));
if(mode==='sealed_holdout'){
  const seal=JSON.parse(fs.readFileSync(path.join(dir,'candidate-frozen.json'),'utf8'));
  if(seal.candidate_source_sha256!==candidateHash||
     seal.independent_oracle_sha256!==frozen.private_oracle_sha256)
    throw Error('Candidate is not frozen for sealed blind evaluation');
}
function matchesValue(actual:{path:string;type:string;value:unknown},f:RefField,raw:string){
  if(actual.path!==f.path||actual.type!==f.type)return false;
  if(f.type==='integer'){
    const lexical=Buffer.from(raw,'utf8')
      .subarray(f.value_start_byte,f.value_end_byte).toString('utf8');
    return typeof actual.value==='number'&&Number.isInteger(actual.value)&&
      String(actual.value)===lexical;
  }
  return Object.is(actual.value,f.value);
}
function scoreOne(row:RefRow):Scored{
  const count=blank();count.all++;
  if(row.raw===null||sha(Buffer.from(row.raw,'utf8'))!==row.raw_event_sha256)
    throw Error('Original record bytes are not intact');
  count.rawIdentityMatches++;
  const independentlyScorable=row.oracle_status==='INDEPENDENT_JSON_BYTE_TRUTH';
  count.scorable+=Number(independentlyScorable);
  count.excluded+=Number(!independentlyScorable);
  count.referenceFields+=row.fields.length;
  const candidate=inspectBoundedSourceSpans(row.raw);
  count.reviewCandidates+=Number(candidate.disposition==='REVIEW_ONLY');
  count.rawOnly+=Number(candidate.disposition==='RAW_ONLY');
  count.unsafeReviewGate+=Number(candidate.disposition==='ABSTAIN_UNSAFE');
  count.reviewNoOracle+=Number(!independentlyScorable&&candidate.disposition==='REVIEW_ONLY');
  count.autoPromotions+=Number(candidate.autoPromoted);
  count.jsonCandidate+=Number(candidate.syntax==='json_object');
  count.syslogJsonCandidate+=Number(candidate.syntax==='syslog_json_object');
  if(!independentlyScorable)return count;
  if(candidate.disposition!=='REVIEW_ONLY')count.abstentionScorable++;
  const reference=new Map(row.fields.map(f=>[f.path,f]));
  const observed=new Map(candidate.fields.map(f=>[f.path,f]));
  for(const [fieldName,gold] of reference){
    const actual=observed.get(fieldName);
    if(!actual){count.fn++;continue;}
    const sameValue=matchesValue(actual,gold,row.raw);
    const sameSpan=actual.startByte===gold.value_start_byte&&
      actual.endByte===gold.value_end_byte;
    if(sameValue&&sameSpan)count.tp++;
    else{
      count.fp++;count.fn++;
      count.wrongValue+=Number(!sameValue);
      count.wrongByteOffset+=Number(!sameSpan);
    }
  }
  for(const name of observed.keys())if(!reference.has(name))count.fp++;
  count.exactEvents+=Number(candidate.fields.length===row.fields.length&&
    candidate.fields.length>0&&candidate.fields.every(f=>{
      const expected=reference.get(f.path);
      return !!expected&&matchesValue(f,expected,row.raw)&&
        f.startByte===expected.value_start_byte&&f.endByte===expected.value_end_byte;
    }));
  return count;
}
const total=blank();
const byFamily:Record<string,Scored>={};
for(const row of candidates){
  if(row.split!==mode)continue;
  const item=scoreOne(row);
  add(total,item);
  const bucket=byFamily[row.family]??=blank();
  add(bucket,item);
}
const summary={gate:'SOURCE_TRIPLE_REVIEW_ONLY_NOT_NATIVE_CERTIFICATION',
  mode,candidate_sha256:candidateHash,reference_sha256:frozen.private_oracle_sha256,
  total,byFamily,span_policy:'half_open_exact_UTF8_byte_ranges',
  no_oracle_policy:'UNSCORABLE_NOT_IN_FP_OR_FN',
  candidate_status:'NON_PROMOTABLE_REVIEW_ONLY',
  source_value_and_byte_position_triples:true};
const serialized=JSON.stringify(summary,null,2)+'\n';
const dest=path.join(dir,'bounded-candidate-'+mode+'.json');
if(fs.existsSync(dest)&&fs.readFileSync(dest,'utf8')!==serialized)
  throw Error('Already scored this cohort with a different candidate: preserve observation');
if(!fs.existsSync(dest))fs.writeFileSync(dest,serialized,{mode:0o600,flag:'wx'});
console.log('BLIND_BOUNDED_STRUCTURE '+JSON.stringify(summary));
if(total.wrongValue||total.wrongByteOffset||total.autoPromotions||
   total.rawIdentityMatches!==total.all)process.exitCode=1;
