/** Independent third-repository partial-field source oracle audit.
 *
 * Only fields asserted in the upstream C test are scorable: no full event
 * exactness, false positive counting on unasserted fields, vendor certification,
 * or auto-promotion is possible.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {parseSyslogEnvelope} from '../../src/syslogEnvelope';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';
type Field={name:string;type:string;value:string;start_byte:number;end_byte:number};
type Sample={id:string;status:string;raw?:string|null;raw_sha256?:string;raw_bytes?:number;
  fields:Field[];reason_code?:string};
type Counts={allCases:number;scorablePartial:number;unscorable:number;
  independentlyAssertedFields:number;baselineMatchedValues:number;
  baselineWrongOrAbsentValues:number;candidateMatchedValues:number;
  candidateWrongOrAbsentValues:number;candidateExactByteTriples:number;
  candidateWrongValueOrByteTriples:number;candidateAbstainedScorable:number;
  candidateReviewScorable:number;candidateReviewUnscorable:number;
  missingRawData:number;rawPreserved:number;sourceByteDrift:number;
  autoPromoted:number;maxCandidateBranches:number};
const zero=():Counts=>({allCases:0,scorablePartial:0,unscorable:0,
  independentlyAssertedFields:0,baselineMatchedValues:0,
  baselineWrongOrAbsentValues:0,candidateMatchedValues:0,
  candidateWrongOrAbsentValues:0,candidateExactByteTriples:0,
  candidateWrongValueOrByteTriples:0,candidateAbstainedScorable:0,
  candidateReviewScorable:0,candidateReviewUnscorable:0,
  missingRawData:0,rawPreserved:0,sourceByteDrift:0,
  autoPromoted:0,maxCandidateBranches:0});
const sha=(data:Buffer|string)=>crypto.createHash('sha256').update(data).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-syslogng-independent-20261017');
const frozen=JSON.parse(fs.readFileSync(path.join(root,'partial-summary.pinned.json'),'utf8'));
const pinned=fs.readFileSync(path.join(root,'source.pinned.json'));
const data=fs.readFileSync(path.join(root,'partial-source-oracle.pinned.json'));
if(frozen.stage!=='FROZEN_BEFORE_ANY_CANDIDATE_SCORING'||
   sha(pinned)!==frozen.source_manifest_sha256||
   sha(data)!==frozen.private_oracle_sha256)
  throw Error('Independent partial source truth not frozen');
const candidates=JSON.parse(data.toString('utf8')) as Sample[];
if(candidates.length!==frozen.stats.cases||
   candidates.reduce((n,r)=>n+r.fields.length,0)!==frozen.stats.scoped_field_triples)
  throw Error('Independent reference denominator changed');
const base=path.resolve(__dirname,'../../src/poc/generalSyslogEnvelopeSpans.ts');
const candidateSourceSha=sha(fs.readFileSync(base));
const priorFreeze=JSON.parse(fs.readFileSync(
  path.join(os.homedir(),'.local/state/parserstudio-syslog-conformance-20261017/candidate-frozen.json'),'utf8'));
if(priorFreeze.candidate_sha256!==candidateSourceSha||
  priorFreeze.state!=='FROZEN_AFTER_DEV_BEFORE_SEALED_HOLDOUT')
  throw Error('PoC candidate has changed after previous independent holdout');
const result=zero();
const misses:string[]=[];
for(const row of candidates){
  result.allCases++;
  const qualified=row.status==='PARTIAL_UPSTREAM_ASSERTED_SOURCE_TRUTH';
  if(qualified)result.scorablePartial++;
  else result.unscorable++;
  if(row.raw==null){result.missingRawData++;continue;}
  const original=Buffer.from(row.raw,'utf8');
  if(sha(original)!==row.raw_sha256||original.length!==row.raw_bytes){
    result.sourceByteDrift++;throw Error('Original source bytes not identical');
  }
  const baseline=parseSyslogEnvelope(row.raw);
  const candidate=inspectGeneralSyslogEnvelope(row.raw);
  result.rawPreserved+=Number(candidate.originalRaw===row.raw&&candidate.sourceBytes===original.length);
  result.autoPromoted+=Number(candidate.autoPromoted);
  result.maxCandidateBranches=Math.max(result.maxCandidateBranches,candidate.branchAttempts);
  if(!qualified){
    result.candidateReviewUnscorable+=Number(candidate.disposition==='REVIEW_ONLY');
    continue;
  }
  result.independentlyAssertedFields+=row.fields.length;
  result.candidateAbstainedScorable+=Number(candidate.disposition!=='REVIEW_ONLY');
  result.candidateReviewScorable+=Number(candidate.disposition==='REVIEW_ONLY');
  const values=new Map(candidate.fields.map(f=>[f.name,f]));
  for(const expected of row.fields){
    let baselineValue:string|undefined;
    if(baseline){
      const field=expected.name as keyof typeof baseline;
      const found=baseline[field];
      if(typeof found==='string')baselineValue=found;
    }
    if(baselineValue===expected.value)result.baselineMatchedValues++;
    else result.baselineWrongOrAbsentValues++;
    const got=values.get(expected.name);
    if(got&&got.value===expected.value&&got.type===expected.type)
      result.candidateMatchedValues++;
    else result.candidateWrongOrAbsentValues++;
    if(got&&got.value===expected.value&&got.type===expected.type&&
       got.startByte===expected.start_byte&&got.endByte===expected.end_byte){
      result.candidateExactByteTriples++;
    }else{
      result.candidateWrongValueOrByteTriples++;
      misses.push(row.id+':'+expected.name);
    }
  }
}
const output={gate:'INDEPENDENT_UPSTREAM_PARTIAL_EXPECTATIONS_ONLY',
  qualification:'PARTIAL_ASSERTED_FIELDS_NOT_COMPLETE_EVENT_GOLDEN',
  cannotScoreUnassertedFieldFP:true,
  cannotScoreFullEventExactness:true,
  baselineDoesNotExposeOriginalUTF8Spans:true,
  candidateSourceSha,candidateCannotAutoPromote:true,
  pinSha:frozen.source_manifest_sha256,referenceSha:frozen.private_oracle_sha256,
  result,missesByOpaqueSourceFieldId:misses};
const serialized=JSON.stringify(output,null,2)+'\n';
const saved=path.join(root,'first-partial-field-comparison.pinned.json');
if(fs.existsSync(saved)&&fs.readFileSync(saved,'utf8')!==serialized)
  throw Error('First blind outcome already frozen; do not revise or selectively rescore');
if(!fs.existsSync(saved))fs.writeFileSync(saved,serialized,{mode:0o600,flag:'wx'});
console.log('SYSLOGNG_INDEPENDENT_PARTIAL_SOURCE_HOLDOUT '+JSON.stringify({
 ...output,missesByOpaqueSourceFieldId:undefined
}));
if(result.sourceByteDrift||result.autoPromoted||result.maxCandidateBranches>2||
   result.independentlyAssertedFields!==frozen.stats.scoped_field_triples)
  process.exitCode=1;
