/** Historical safety replay, not an independent accuracy holdout. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import {arbitrateIndependentLeef} from '../../src/poc/independentLeefSource';
import {arbitrateOptionalIndependentCsv,inspectIndependentQuotedCsv}
  from '../../src/poc/independentQuotedCsvSource';
const state=path.join(os.homedir(),'.local/state');
const sha=(buf:Buffer)=>crypto.createHash('sha256').update(buf).digest('hex');
const groups=[
 ['parserstudio-fresh-vendor-holdout-20261016','records.json','3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',571,false],
 ['parserstudio-ext-holdout-20261016','records.json','dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',790,false],
 ['parserstudio-fresh-vendor-holdout-20261016','known_invalid.json','da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',1,true],
 ['parserstudio-ext-holdout-20261016','adversarial.json','9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',1532,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bare_mutations.json','389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',45,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bracket_mutations.json','5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',414,true],
 ['parserstudio-fresh-vendor-holdout-20261016','sophos_kv_mutations.json','1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',900,true],
] as const;
const report={historicalOriginals:0,historicalInvalid:0,oldInvalidLexicalReview:0,
  newReviewInvalid:0,oldResultsChanged:0,byteDrift:0,utf8SpanDrift:0,
  autoPromotion:0,attemptsOver8:0,vetoEscape:0,
  previousIndependentSourceEvents:0,previousIndependentChanged:0};
function validate(raw:string,invalid:boolean,priorIndependent:boolean){
 const before=arbitrateIndependentLeef(raw);
 const after=arbitrateOptionalIndependentCsv(raw);
 if(JSON.stringify(before)!==JSON.stringify(after))
   if(priorIndependent)report.previousIndependentChanged++;else report.oldResultsChanged++;
 const buf=Buffer.from(raw,'utf8');
 if(after.raw!==raw||after.sourceBytes!==buf.length)report.byteDrift++;
 if(after.autoPromoted||after.independentOracleCertified||after.nativeVerified)
   report.autoPromotion++;
 if(after.branchAttempts>8)report.attemptsOver8++;
 for(const field of [...after.envelopeFields,...after.bodyClaims])
   if(buf.subarray(field.startByte,field.endByte).toString('utf8')!==field.rawSpanValue)
     report.utf8SpanDrift++;
 if(invalid){
   const previously=before.disposition.startsWith('REVIEW_ONLY');
   const currently=after.disposition.startsWith('REVIEW_ONLY');
   report.oldInvalidLexicalReview+=Number(previously);
   report.newReviewInvalid+=Number(currently&&!previously);
   if(currently){
     const veto=arbitrateOptionalIndependentCsv(raw,undefined,{
       sourceIdentity:'MATCH',structuralProfile:'VETO',
       independentSourceTruth:'UNSCORED'});
     if(veto.disposition!=='ABSTAIN_UNSAFE'||veto.autoPromoted)
       report.vetoEscape++;
   }
 }
 // No external framing means even arbitrary CSV-looking strings cannot expose
 // a new positional field, regardless of their previous grammar category.
 const unframed=inspectIndependentQuotedCsv(raw);
 if(unframed.positionalClaims.length||unframed.namedClaims.length||
    unframed.autoPromoted)report.autoPromotion++;
}
for(const [directory,filename,expectedSha,count,invalid] of groups){
 const buf=fs.readFileSync(path.join(state,directory,filename));
 if(sha(buf)!==expectedSha)throw Error('Frozen historic source SHA drift');
 const rows=JSON.parse(buf.toString('utf8')) as Array<{raw:string}>;
 if(rows.length!==count)throw Error('Historical source denominator drift');
 for(const row of rows){
   if(invalid)report.historicalInvalid++;else report.historicalOriginals++;
   validate(row.raw,invalid,false);
 }
}
for(const [directory,name,digest,count] of [
 ['parserstudio-independent-nonjson-20261017','upstream-authored-original-goldens.v2.json',
  '18c25739376c4bd7289066e147ac73fc5e55344385b0312e7c0e6cab00cea17b',16],
 ['parserstudio-independent-transfer-20261017','source-transfer-original-goldens.v1.json',
  '6944e92d0e5f0f8c4db9fe96a7d05ea0a07a68cb111db2e9bb17c97ddfb2a07b',3],
 ['parserstudio-independent-leef-20261017','leef-upstream-original-goldens.v1.json',
  '7c66600785630316ec29ae936048a78119def5060cceadb4276aa9cecbf41aff',3],
] as const){
 const buf=fs.readFileSync(path.join(state,directory,name));
 if(sha(buf)!==digest)throw Error('Earlier frozen independent original SHA drift');
 const data=JSON.parse(buf.toString('utf8')) as Array<{raw:string;status:string}>;
 const selected=data.filter(x=>x.status==='SCORABLE_SOURCE_ONLY');
 if(selected.length!==count)throw Error('Earlier source exact cohort denominator drift');
 for(const entry of selected){
   report.previousIndependentSourceEvents++;
   validate(entry.raw,false,true);
 }
}
const summary={...report,scope:'PREVIOUSLY_FROZEN_SAFETY_REPLAY_NOT_NEW_ACCURACY',
  independentCsvContextAddedToProduct:false,sourceNativeCertified:false};
console.log('INDEPENDENT_CSV_HISTORICAL '+JSON.stringify(summary));
if(report.historicalOriginals!==1361||report.historicalInvalid!==2892||
   report.previousIndependentSourceEvents!==22||report.oldInvalidLexicalReview!==197||
   report.newReviewInvalid||report.oldResultsChanged||report.previousIndependentChanged||
   report.byteDrift||report.utf8SpanDrift||report.autoPromotion||
   report.attemptsOver8||report.vetoEscape)process.exitCode=1;
