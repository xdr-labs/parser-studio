/** Scored only on v2 independently authored CrowdsSec source expectation.
 * v2 is explicitly a post-baseline contract correction, not fresh blinded data.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';
import {inspectRfc3164WithoutPri} from '../../src/poc/publisherQualifiedUnprioritizedSyslog';
const expectedHash='d5f1766454bab304be4031c47ac136c88e67e6d941f6120260b52da02b3c1e0a';
const filename=path.join(os.homedir(),'.local/state/parserstudio-new-independent-security-20261017/crowdsec-source-only-corrected-expected.v2.json');
const blob=fs.readFileSync(filename);
const sha=(value:Buffer)=>crypto.createHash('sha256').update(value).digest('hex');
if(sha(blob)!==expectedHash)throw Error('Post-baseline source reference digest mismatch');
type Field={canonical_field:string;value:string;startByte:number;endByte:number};
type Row={raw:string;source_file:string;status:string;fields:Field[]};
const rows=JSON.parse(blob.toString('utf8')) as Row[];
type Metrics={originals:number;scorableOriginals:number;referenceFields:number;
 baselineHit:number;candidateHit:number;candidateWrongSameName:number;
 candidateByteDrift:number;unexpectedStatusChanges:number;qualifiedNewSourceEvents:number;};
const result:Metrics={originals:0,scorableOriginals:0,referenceFields:0,
 baselineHit:0,candidateHit:0,candidateWrongSameName:0,candidateByteDrift:0,
 unexpectedStatusChanges:0,qualifiedNewSourceEvents:0};
const byOrigin:Record<string,{reference:number;oldHit:number;newHit:number;originals:number}>={};
const match=(claims:Array<{name:string;value:string;startByte:number;endByte:number}>,f:Field)=>
 claims.some(c=>c.name===f.canonical_field&&c.value===f.value&&
   c.startByte===f.startByte&&c.endByte===f.endByte);
for(const row of rows){
 result.originals++;
 const origin=row.source_file.split('/').at(-1)!;
 const summary=byOrigin[origin]??{reference:0,oldHit:0,newHit:0,originals:0};
 byOrigin[origin]=summary;summary.originals++;
 const old=inspectGeneralSyslogEnvelope(row.raw);
 const isPublisherKnownBareSyslog=row.source_file.endsWith('/syslog-logs.log');
 const candidate=old.disposition==='REVIEW_ONLY'||!isPublisherKnownBareSyslog?old:
   inspectRfc3164WithoutPri(row.raw,isPublisherKnownBareSyslog?
      {sourceFraming:'PUBLISHER_ASSERTED_BSD_WITHOUT_PRI'}:undefined);
 if(candidate.originalRaw!==row.raw||candidate.sourceBytes!==Buffer.byteLength(row.raw,'utf8'))
  result.candidateByteDrift++;
 for(const field of candidate.fields){
  if(Buffer.from(row.raw,'utf8').subarray(field.startByte,field.endByte)
     .toString('utf8')!==field.value)result.candidateByteDrift++;
 }
 if(!isPublisherKnownBareSyslog&&JSON.stringify(candidate)!==JSON.stringify(old))
   result.unexpectedStatusChanges++;
 if(isPublisherKnownBareSyslog&&candidate.disposition==='REVIEW_ONLY')
   result.qualifiedNewSourceEvents++;
 if(row.status!=='PARTIAL_SCORABLE')continue;
 result.scorableOriginals++;
 for(const f of row.fields){
  summary.reference++;result.referenceFields++;
  if(match(old.fields,f)){result.baselineHit++;summary.oldHit++;}
  if(match(candidate.fields,f)){result.candidateHit++;summary.newHit++;}
  else if(candidate.fields.some(c=>c.name===f.canonical_field))
   result.candidateWrongSameName++;
 }
}
const output={scope:'PUBLISHER_ASSERTED_PARTIAL_SOURCE_FIELDS_NO_TARGET',
 frozenExpected:expectedHash,correction:'v2 reclassifies upstream raw pass-through as non-field post-baseline',
 reportedCandidateSyntax:'OPT_IN_PUBLISHER_QUALIFIED_PRI_LESS_RFC3164',
 ...result,byOrigin,
 unqualifiedAdditionalFieldsFP:'UNSCORABLE_PARTIAL_ASSERTION_ONLY',
 manufacturerEscapes:'NOT_CERTIFIED',nativeStellar:'NOT_VERIFIED',
 autoPromotions:false,rawSourcePrinted:false};
console.log('PUBLISHER_QUALIFIED_MIXED_ENVELOPE_SOURCE '+JSON.stringify(output));
if(result.originals!==17||result.referenceFields!==16||
 result.candidateByteDrift||result.unexpectedStatusChanges||
 result.candidateWrongSameName)process.exitCode=1;
