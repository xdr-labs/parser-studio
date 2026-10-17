/** Pre-frozen upstream Syslog conformance oracle vs isolated source-span observer.
 *
 * A Go library's expected fields are not manufacturer/Fluentd qualification.
 * Synthetic mutations and unsupported upstream cases are never put in TP/FN.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';
type Expected={name:string;type:string;value:string;start_byte:number;end_byte:number};
type Row={id:string;split:'development'|'sealed';status:string;source_id:string;
  raw?:string|null;raw_sha256?:string;raw_bytes?:number;
  expected_grammar?:string;fields:Expected[]};
type Counts={total:number;scorable:number;negative:number;unscorable:number;fields:number;
  reviewScorable:number;abstainScorable:number;exactEvents:number;
  tp:number;fp:number;fn:number;valueMismatch:number;byteOffsetMismatch:number;
  reviewedKnownInvalid:number;reviewedUnscorable:number;autoPromotions:number;
  rawPreserved:number;maxBranchAttempts:number;sourceIdentityError:number};
const blank=():Counts=>({total:0,scorable:0,negative:0,unscorable:0,fields:0,
  reviewScorable:0,abstainScorable:0,exactEvents:0,tp:0,fp:0,fn:0,
  valueMismatch:0,byteOffsetMismatch:0,reviewedKnownInvalid:0,
  reviewedUnscorable:0,autoPromotions:0,rawPreserved:0,maxBranchAttempts:0,
  sourceIdentityError:0});
const add=(dest:Counts,src:Counts)=>{for(const k of Object.keys(dest) as (keyof Counts)[]) {
  if(k==='maxBranchAttempts')dest[k]=Math.max(dest[k],src[k]);
  else dest[k]+=src[k];
}};
const sha=(data:Buffer|string)=>crypto.createHash('sha256').update(data).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-syslog-conformance-20261017');
const mode=process.argv[2]??'development';
if(mode!=='development'&&mode!=='sealed')throw Error('Explicit evaluation cohort required');
const pin=fs.readFileSync(path.join(root,'sources.pinned.json'));
const summary=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v3.pinned.json'),'utf8'));
const data=fs.readFileSync(path.join(root,'records-and-expected.v3.pinned.json'));
if(sha(pin)!==summary.source_manifest_sha256||sha(data)!==summary.private_oracle_sha256)
  throw Error('Pinned independent upstream conformance oracle changed');
const source=path.resolve(__dirname,'../../src/poc/generalSyslogEnvelopeSpans.ts');
const candidateSha=sha(fs.readFileSync(source));
if(mode==='sealed'){
  const frozen=JSON.parse(fs.readFileSync(path.join(root,'candidate-frozen.json'),'utf8'));
  if(frozen.candidate_sha256!==candidateSha||
     frozen.reference_sha256!==summary.private_oracle_sha256)
    throw Error('Holdout cannot score an unfrozen or modified candidate');
}
const rows=JSON.parse(data.toString('utf8')) as Row[];
if(rows.length!==summary.all_cases||
   rows.reduce((n,r)=>n+r.fields.length,0)!==summary.source_field_triples)
  throw Error('Independent fixed denominator changed');
const total=blank();
const groups:Record<string,Counts>={};
for(const row of rows){
  if(row.split!==mode)continue;
  const one=blank();one.total++;
  one.scorable+=Number(row.status==='INDEPENDENT_UPSTREAM_CONFORMANCE_FIELDS');
  one.negative+=Number(row.status==='NEGATIVE_ONLY');
  one.unscorable+=Number(row.status==='UNSCORABLE');
  one.fields+=row.fields.length;
  if(row.raw!==null&&row.raw!==undefined){
    const original=Buffer.from(row.raw,'utf8');
    if(sha(original)!==row.raw_sha256||original.length!==row.raw_bytes)
      throw Error('Original raw event identity drifted');
    const observed=inspectGeneralSyslogEnvelope(row.raw);
    one.maxBranchAttempts=observed.branchAttempts;
    one.rawPreserved+=Number(observed.originalRaw===row.raw);
    one.autoPromotions+=Number(observed.autoPromoted);
    if(row.status==='NEGATIVE_ONLY')
      one.reviewedKnownInvalid+=Number(observed.disposition==='REVIEW_ONLY');
    else if(row.status==='UNSCORABLE')
      one.reviewedUnscorable+=Number(observed.disposition==='REVIEW_ONLY');
    else{
      one.reviewScorable+=Number(observed.disposition==='REVIEW_ONLY');
      one.abstainScorable+=Number(observed.disposition!=='REVIEW_ONLY');
      const expected=new Map(row.fields.map(f=>[f.name,f]));
      const fields=new Map(observed.fields.map(f=>[f.name,f]));
      let exact=observed.fields.length===row.fields.length;
      for(const [name,exp] of expected){
        const got=fields.get(name);
        if(!got){one.fn++;exact=false;continue;}
        const correctValue=got.type===exp.type&&got.value===exp.value;
        const correctSpan=got.startByte===exp.start_byte&&got.endByte===exp.end_byte;
        if(correctValue&&correctSpan)one.tp++;
        else{
          one.fp++;one.fn++;exact=false;
          one.valueMismatch+=Number(!correctValue);
          one.byteOffsetMismatch+=Number(!correctSpan);
        }
      }
      for(const name of fields.keys())if(!expected.has(name)){
        one.fp++;exact=false;
      }
      one.exactEvents+=Number(exact&&observed.disposition==='REVIEW_ONLY'&&row.fields.length>0);
    }
  }
  add(total,one);
  const group=groups[row.source_id]??=blank();
  add(group,one);
}
const report={cohort:mode,reference_sha:summary.private_oracle_sha256,
  candidate_source_sha:candidateSha,
  semantic_contract:'UPSTREAM_LIBRARY_EXPECTED_SOURCE_FIELDS_NOT_STELLAR',
  source_byte_contract:'HALF_OPEN_ORIGINAL_UTF8_OFFSETS',
  automatic_promotions_allowed:false,
  unscorable_policy:'EXCLUDED_FROM_FP_FN_NO_CREDIT',total,groups};
const serialized=JSON.stringify(report,null,2)+'\n';
const output=path.join(root,'candidate-'+mode+'-'+candidateSha.slice(0,12)+'.json');
if(fs.existsSync(output)&&fs.readFileSync(output,'utf8')!==serialized)
  throw Error('Frozen observation cannot be silently re-scored');
if(!fs.existsSync(output))fs.writeFileSync(output,serialized,{mode:0o600,flag:'wx'});
console.log('SYSLOG_CONFORMANCE_CANDIDATE '+JSON.stringify(report));
if(total.sourceIdentityError||total.autoPromotions||total.rawPreserved!==
   total.scorable+total.negative+total.unscorable-
   rows.filter(r=>r.split===mode&&r.raw==null).length)
  process.exitCode=1;
