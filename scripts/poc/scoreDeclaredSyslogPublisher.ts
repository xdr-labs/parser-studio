/** Compare the same frozen manufacturer-declared/publisher-valued partial source
 * tuples without allowing reference fields to select the candidate profile.
 * No original logs or expected values are printed or committed.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';
import {inspectDeclaredSourceHeader,type DeclaredSourceHeaderProfile} from '../../src/poc/declaredSyslogHeader';

const pinnedSha='64b4ababf7c701c8226575dde2e4e4690cb1c6c8f69c6981bd47d9a2b41a0e2f';
const file=path.join(os.homedir(),
 '.local/state/parserstudio-declared-syslog-publisher-20261017',
 'declared-cisco-source-oracle.v1.json');
const blob=fs.readFileSync(file);
if(crypto.createHash('sha256').update(blob).digest('hex')!==pinnedSha)
 throw new Error('Independent pre-candidate publisher oracle SHA mismatch');
type OracleField={name:string;value:string;startByte:number;endByte:number};
type OracleRow={raw:string;rawSha256:string;status:string;fields:OracleField[];
 sourceFile:string;line:number};
const rows=JSON.parse(blob.toString('utf-8')) as OracleRow[];
// Public, independently documented metadata schema; no Cisco-specific
// matching is coded in the generic observer being evaluated.
const contract:DeclaredSourceHeaderProfile={
 framing:'INDEPENDENTLY_DECLARED_RFC3164_ORDERED_BODY_HEADER',
 fields:[
   {name:'cat_name',syntax:'opaque_token'},
   {name:'msg_id',syntax:'unsigned_integer',minimum:1,maximum:4294967295},
   {name:'total_seg',syntax:'unsigned_integer',minimum:1,maximum:1000},
   {name:'seg_num',syntax:'unsigned_integer',minimum:0,maximum:1000},
 ],
};
const m=(arr:OracleField[],f:OracleField)=>
 arr.some(a=>a.name===f.name&&a.value===f.value&&
    a.startByte===f.startByte&&a.endByte===f.endByte);
const sameName=(arr:OracleField[],f:OracleField)=>arr.some(a=>a.name===f.name);
const stats={originals:0,partialScorable:0,unscorable:0,expectedTuples:0,
 oldExact:0,newExact:0,oldMissing:0,newMissing:0,
 oldSameNameMismatch:0,newSameNameMismatch:0,
 candidateReview:0,candidateAbstain:0,unknownCandidateClaims:0,
 unscorableCandidateReview:0,unscorableCandidateClaims:0,
 sourceDrift:0,autoPromotions:0,maxBranches:0,maxDepth:0};
for(const row of rows){
 if(crypto.createHash('sha256').update(row.raw,'utf8').digest('hex')!==row.rawSha256)
  throw new Error('Frozen original per-message hash drift');
 stats.originals++;
 stats.partialScorable+=Number(row.fields.length>0);
 stats.unscorable+=Number(row.fields.length===0);
 const previous=inspectGeneralSyslogEnvelope(row.raw);
 const qualified=inspectDeclaredSourceHeader(row.raw,contract);
 const unknown=inspectDeclaredSourceHeader(row.raw);
 stats.unknownCandidateClaims+=unknown.fields.length+
  Number(unknown.disposition==='REVIEW_ONLY');
 stats.candidateReview+=Number(qualified.disposition==='REVIEW_ONLY');
 stats.candidateAbstain+=Number(qualified.disposition!=='REVIEW_ONLY');
 if(!row.fields.length){
   stats.unscorableCandidateReview+=Number(qualified.disposition==='REVIEW_ONLY');
   stats.unscorableCandidateClaims+=qualified.fields.length;
 }
 const b=Buffer.from(row.raw,'utf8');
 for(const v of [previous,qualified]){
  stats.sourceDrift+=Number(v.sourceBytes!==b.length||v.originalRaw!==row.raw);
  stats.autoPromotions+=Number(v.autoPromoted||v.nativeParser!=='NOT_VERIFIED');
  for(const f of v.fields){
    stats.sourceDrift+=Number(b.subarray(f.startByte,f.endByte).toString('utf8')!==f.value);
  }
 }
 stats.maxBranches=Math.max(stats.maxBranches,qualified.branchAttempts);
 stats.maxDepth=Math.max(stats.maxDepth,qualified.maxDepth);
 for(const expected of row.fields){
  stats.expectedTuples++;
  const p=m(previous.fields,expected);
  const q=m(qualified.fields,expected);
  stats.oldExact+=Number(p);stats.newExact+=Number(q);
  stats.oldMissing+=Number(!p);stats.newMissing+=Number(!q);
  stats.oldSameNameMismatch+=Number(!p&&sameName(previous.fields,expected));
  stats.newSameNameMismatch+=Number(!q&&sameName(qualified.fields,expected));
 }
}
const summary={
 scope:'NEW_PINNED_PUBLISHER_SOURCES_WITH_AUTHORITATIVE_DECLARED_FIELD_NAMES',
 externalFieldContract:'CISCO_OFFICIAL_DOCUMENTED_ORDER',
 oracleSha256:pinnedSha,oracleFrozenBeforeCandidate:true,
 ...stats,additionalExactPartialFields:stats.newExact-stats.oldExact,
 extraSourceFieldFP:'UNSCORABLE_PARTIAL_REFERENCE',
 wholeEventExact:'UNSCORABLE_PARTIAL_REFERENCE',
 trueDeviceWireCapture:'NOT_PROVEN',
 expectedByteLocations:'EVALUATOR_DERIVED_FROM_PUBLISHER_EXPECTED_VALUES',
 escapedValueDecoded:'UNSCORABLE',
 emptyNilMissingSemantics:'UNSCORABLE',
 nativeStellar:'NOT_VERIFIED',
 rawOrExpectedSourceValuesPrinted:false,
};
console.log('DECLARED_PUBLISHER_SYSLOG_SOURCE_SCORE '+JSON.stringify(summary));
if(stats.originals!==69||stats.expectedTuples!==245||
 stats.newExact<stats.oldExact||
 stats.newSameNameMismatch>stats.oldSameNameMismatch||
 stats.sourceDrift||stats.autoPromotions||stats.unknownCandidateClaims||
 stats.maxBranches>3||stats.maxDepth>1)process.exitCode=1;
