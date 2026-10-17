/** Frozen, externally authored partial source oracle; private values never committed.
 * Publisher assertions (Elastic ECS) do not certify Cisco firmware semantics.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';
import {inspectPublisherQualifiedBareTag} from '../../src/poc/publisherQualifiedBareTag';

const ORACLE_SHA='7453879258705368c551c357fd46c0901f31e23ebee401f1bb424d006787da2c';
const file=path.join(os.homedir(),
  '.local/state/parserstudio-elastic-cisco-ise-independent-20261017',
  'publisher-cisco-ise-oracle.v1.json');
const data=fs.readFileSync(file);
const digest=crypto.createHash('sha256').update(data).digest('hex');
if(digest!==ORACLE_SHA)throw new Error('Immutable independently authored oracle drifted');
type Field={name:string;value:string;startByte:number;endByte:number};
type Row={raw:string;originalSha256:string;sourceFile:string;line:number;
 qualification:string;fields:Field[];decodedManufacturerEscape:string;
 emptyVsNilVsAbsent:string;native:string};
const originalRows=JSON.parse(data.toString('utf8')) as Row[];
type Counter={originals:number;scorable:number;unscorable:number;expected:number;
 oldTp:number;newTp:number;oldFn:number;newFn:number;
 oldAssertedNameFp:number;newAssertedNameFp:number;
 oldSpanOrValueMismatch:number;newSpanOrValueMismatch:number;
 addedVerified:number;publisherGated:number;qualifiedAbstain:number;unqualifiedClaims:number;
 sourceByteDrift:number;unsafelyPromoted:number;maxBranches:number;maxDepth:number};
const stats:Counter={originals:0,scorable:0,unscorable:0,expected:0,
 oldTp:0,newTp:0,oldFn:0,newFn:0,oldAssertedNameFp:0,newAssertedNameFp:0,
 oldSpanOrValueMismatch:0,newSpanOrValueMismatch:0,addedVerified:0,publisherGated:0,
 qualifiedAbstain:0,unqualifiedClaims:0,sourceByteDrift:0,unsafelyPromoted:0,
 maxBranches:0,maxDepth:0};
const match=(arr:Field[],f:Field)=>
 arr.some(x=>x.name===f.name&&x.value===f.value&&
   x.startByte===f.startByte&&x.endByte===f.endByte);
const sameName=(arr:Field[],f:Field)=>arr.some(x=>x.name===f.name);
for(const row of originalRows){
 const rawHash=crypto.createHash('sha256').update(row.raw,'utf8').digest('hex');
 if(rawHash!==row.originalSha256)throw new Error('Independent original hash drift');
 stats.originals++;
 stats.scorable+=Number(row.fields.length>0);
 stats.unscorable+=Number(row.fields.length===0);
 const old=inspectGeneralSyslogEnvelope(row.raw);
 const withIndependentProfile=row.fields.some(f=>f.name==='appname');
 const candidate=inspectPublisherQualifiedBareTag(row.raw,
   withIndependentProfile?
     {sourceFraming:'PUBLISHER_ASSERTED_RFC3164_BARE_APP_TAG'}:undefined);
 stats.publisherGated+=Number(withIndependentProfile);
 stats.qualifiedAbstain+=Number(withIndependentProfile&&candidate.disposition!=='REVIEW_ONLY');
 const noProfile=inspectPublisherQualifiedBareTag(row.raw);
 stats.unqualifiedClaims+=noProfile.fields.length+Number(noProfile.disposition==='REVIEW_ONLY');
 stats.maxBranches=Math.max(stats.maxBranches,candidate.branchAttempts);
 stats.maxDepth=Math.max(stats.maxDepth,candidate.maxDepth);
 const bytes=Buffer.from(row.raw,'utf8');
 for(const v of [old,candidate]){
   stats.sourceByteDrift+=Number(v.originalRaw!==row.raw||v.sourceBytes!==bytes.length);
   stats.unsafelyPromoted+=Number(v.autoPromoted||v.nativeParser!=='NOT_VERIFIED');
   for(const field of v.fields){
     stats.sourceByteDrift+=Number(bytes.subarray(field.startByte,field.endByte)
       .toString('utf8')!==field.value);
   }
 }
 for(const expected of row.fields){
   stats.expected++;
   const o=match(old.fields,expected);
   const n=match(candidate.fields,expected);
   stats.oldTp+=Number(o);stats.newTp+=Number(n);
   stats.oldFn+=Number(!o);stats.newFn+=Number(!n);
   stats.addedVerified+=Number(n&&!o);
   stats.oldAssertedNameFp+=Number(!o&&sameName(old.fields,expected));
   stats.newAssertedNameFp+=Number(!n&&sameName(candidate.fields,expected));
   stats.oldSpanOrValueMismatch+=Number(!o&&sameName(old.fields,expected));
   stats.newSpanOrValueMismatch+=Number(!n&&sameName(candidate.fields,expected));
 }
}
const summary={cohort:'ELASTIC_PUBLISHER_CISCO_ISE_ORIGINAL_TEST_FIXTURES',
 upstreamSha:'615252c0910be1b8dc4dbe8f70acabe02ea8757e',
 oracleSha256:ORACLE_SHA,oracleFrozenBeforeScoring:true,
 ...stats,
 comparison:'IDENTICAL_FROZEN_PARTIAL_ASSERTED_FIELD_DENOMINATOR',
 fpScope:'ASSERTED_SAME_NAME_MISMATCH_ONLY_UNASSERTED_FIELD_FP_UNSCORABLE',
 wholeEventExact:'UNSCORABLE_INCOMPLETE_PUBLISHER_ORACLE',
 manufacturerEscapeSemantics:'NOT_CERTIFIED',
 manufacturerEmptySemantics:'NOT_CERTIFIED',
 nestedMixedForwarder:'UNSCORABLE_NO_INDEPENDENT_PAIRED_ORIGINAL',
 historical197:'SAFETY_REPLAY_ONLY',
 autoPromotion:false,nativeStellar:'NOT_VERIFIED',
 valuesPrinted:false};
console.log('ELASTIC_PUBLISHER_BARE_SYSLOG_SOURCE '+JSON.stringify(summary));
if(stats.originals!==149||stats.expected!==590||
 stats.sourceByteDrift||stats.newAssertedNameFp>stats.oldAssertedNameFp||
 stats.unsafelyPromoted||stats.unqualifiedClaims||stats.newTp<stats.oldTp||
 stats.maxBranches>3||stats.maxDepth>1)process.exitCode=1;
