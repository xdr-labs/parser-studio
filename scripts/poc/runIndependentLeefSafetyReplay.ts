/** Source-only safety replay. OLD corpora are NEVER a fresh accuracy score. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
import {arbitrateIndependentLeef} from '../../src/poc/independentLeefSource';
const state=path.join(os.homedir(),'.local/state');
const sha=(x:Buffer)=>crypto.createHash('sha256').update(x).digest('hex');
const historical=[
 ['parserstudio-fresh-vendor-holdout-20261016','records.json','3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',571,false],
 ['parserstudio-ext-holdout-20261016','records.json','dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',790,false],
 ['parserstudio-fresh-vendor-holdout-20261016','known_invalid.json','da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',1,true],
 ['parserstudio-ext-holdout-20261016','adversarial.json','9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',1532,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bare_mutations.json','389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',45,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bracket_mutations.json','5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',414,true],
 ['parserstudio-fresh-vendor-holdout-20261016','sophos_kv_mutations.json','1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',900,true],
] as const;
const report={historicalOriginals:0,historicalInvalid:0,
  historicalKnownReviewInvalid:0,newlyReviewableInvalid:0,
  newReviewOriginals:0,changedNonLeef:0,
  rawByteDrift:0,utf8SpanDrift:0,autoPromotions:0,attemptsOver8:0,
  independentVetoEscape:0,previouslyFrozenIndependentNonLeef:0,
  previouslyFrozenNonLeefChanged:0};
function verify(raw:string,invalid:boolean,previouslyQualified:boolean){
 const before=arbitrateIndependentNonJson(raw);
 const result=arbitrateIndependentLeef(raw);
 const bytes=Buffer.from(raw,'utf8');
 const equal=JSON.stringify(before)===JSON.stringify(result);
 if(!raw.startsWith('LEEF:')&&!equal)
   if(previouslyQualified)report.previouslyFrozenNonLeefChanged++;
   else report.changedNonLeef++;
 if(result.raw!==raw||result.sourceBytes!==bytes.length)report.rawByteDrift++;
 if(result.autoPromoted||result.nativeVerified||result.independentOracleCertified)
   report.autoPromotions++;
 if(result.branchAttempts>8)report.attemptsOver8++;
 for(const c of [...result.envelopeFields,...result.bodyClaims])
   if(bytes.subarray(c.startByte,c.endByte).toString('utf8')!==c.rawSpanValue)
     report.utf8SpanDrift++;
 if(invalid){
   if(before.disposition.startsWith('REVIEW_ONLY'))report.historicalKnownReviewInvalid++;
   if(!before.disposition.startsWith('REVIEW_ONLY')&&result.disposition.startsWith('REVIEW_ONLY'))
     report.newlyReviewableInvalid++;
   if(result.disposition.startsWith('REVIEW_ONLY')){
     const after=arbitrateIndependentLeef(raw,{sourceIdentity:'MATCH',
       structuralProfile:'VETO',independentSourceTruth:'UNSCORED'});
     if(after.disposition!=='ABSTAIN_UNSAFE'||after.bodyClaims.length||after.autoPromoted)
       report.independentVetoEscape++;
   }
 }else if(!previouslyQualified&&!before.disposition.startsWith('REVIEW_ONLY')&&
          result.disposition.startsWith('REVIEW_ONLY'))report.newReviewOriginals++;
}
for(const [dir,file,hash,count,invalid] of historical){
 const serialized=fs.readFileSync(path.join(state,dir,file));
 if(sha(serialized)!==hash)throw Error('Historical frozen corpus SHA drift');
 const rows=JSON.parse(serialized.toString('utf8')) as Array<{raw:string}>;
 if(rows.length!==count)throw Error('Historical original mutation count drift');
 for(const row of rows){
   if(invalid)report.historicalInvalid++;else report.historicalOriginals++;
   verify(row.raw,invalid,false);
 }
}
for(const [dir,name,digest,expected] of [
 ['parserstudio-independent-nonjson-20261017','upstream-authored-original-goldens.v2.json',
  '18c25739376c4bd7289066e147ac73fc5e55344385b0312e7c0e6cab00cea17b',16],
 ['parserstudio-independent-transfer-20261017','source-transfer-original-goldens.v1.json',
  '6944e92d0e5f0f8c4db9fe96a7d05ea0a07a68cb111db2e9bb17c97ddfb2a07b',3],
] as const){
 const b=fs.readFileSync(path.join(state,dir,name));
 if(sha(b)!==digest)throw Error('Earlier qualified non-LEEF source SHA changed');
 const rows=JSON.parse(b.toString('utf8')) as Array<{status:string;raw:string}>;
 let selected=0;
 for(const row of rows)if(row.status==='SCORABLE_SOURCE_ONLY'){
   selected++;
   verify(row.raw,false,true);
   report.previouslyFrozenIndependentNonLeef++;
 }
 if(selected!==expected)throw Error('Previously qualified non-LEEF original count drift');
}
console.log('INDEPENDENT_LEEF_HISTORICAL '+JSON.stringify({...report,
  status:'AFFECTED_STAGE_SAFETY_ONLY_NOT_NEW_BLIND_TP',
  sourceCompleteCertified:false,nativeVerified:false}));
if(report.historicalOriginals!==1361||report.historicalInvalid!==2892||
   report.previouslyFrozenIndependentNonLeef!==19||report.newlyReviewableInvalid||
   report.changedNonLeef||report.previouslyFrozenNonLeefChanged||
   report.rawByteDrift||report.utf8SpanDrift||report.autoPromotions||
   report.attemptsOver8||report.independentVetoEscape)
  process.exitCode=1;
