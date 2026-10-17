/** Historical stage-only safety regression: NOT a new independent source-accuracy holdout. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateOptionalIndependentCsv} from '../../src/poc/independentQuotedCsvSource';
import {arbitrateOptionalIndependentLogfmt,inspectIndependentLogfmt}
  from '../../src/poc/independentLogfmtSource';
const state=path.join(os.homedir(),'.local/state');
const sha=(x:Buffer)=>crypto.createHash('sha256').update(x).digest('hex');
const history=[
 ['parserstudio-fresh-vendor-holdout-20261016','records.json','3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',571,false],
 ['parserstudio-ext-holdout-20261016','records.json','dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',790,false],
 ['parserstudio-fresh-vendor-holdout-20261016','known_invalid.json','da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',1,true],
 ['parserstudio-ext-holdout-20261016','adversarial.json','9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',1532,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bare_mutations.json','389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',45,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bracket_mutations.json','5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',414,true],
 ['parserstudio-fresh-vendor-holdout-20261016','sophos_kv_mutations.json','1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',900,true],
] as const;
const previous=[
 ['parserstudio-independent-nonjson-20261017','upstream-authored-original-goldens.v2.json',
  '18c25739376c4bd7289066e147ac73fc5e55344385b0312e7c0e6cab00cea17b',16,'SCORABLE_SOURCE_ONLY'],
 ['parserstudio-independent-transfer-20261017','source-transfer-original-goldens.v1.json',
  '6944e92d0e5f0f8c4db9fe96a7d05ea0a07a68cb111db2e9bb17c97ddfb2a07b',3,'SCORABLE_SOURCE_ONLY'],
 ['parserstudio-independent-leef-20261017','leef-upstream-original-goldens.v1.json',
  '7c66600785630316ec29ae936048a78119def5060cceadb4276aa9cecbf41aff',3,'SCORABLE_SOURCE_ONLY'],
 ['parserstudio-independent-quoted-csv-20261017','author-expected-original-csv.v1.json',
  '21df0514536935d5361e73b5cfbc4a263f8eb796caf27e4214e380d38a29427b',28,'POSITIONAL_SCORABLE'],
] as const;
const report={
 historicalOriginals:0,historicalInvalidMutations:0,
 historicalMalformedReviewOld:0,historicalMalformedReviewNew:0,
 previouslyIndependentNonLogfmt:0,
 resultChanges:0,newMalformedReview:0,originalByteDrift:0,
 replayByteDrift:0,autoPromotions:0,branchBudgetViolations:0,
 independentVetoBypasses:0,explicitFramingClaimsOnUnknown:0,
};
function verify(raw:string,invalid:boolean,independent:boolean):void{
 const before=arbitrateOptionalIndependentCsv(raw);
 const after=arbitrateOptionalIndependentLogfmt(raw);
 if(JSON.stringify(before)!==JSON.stringify(after))report.resultChanges++;
 const original=Buffer.from(raw,'utf8');
 if(after.raw!==raw||after.sourceBytes!==original.length)report.originalByteDrift++;
 if(after.autoPromoted||after.nativeVerified||after.independentOracleCertified)
   report.autoPromotions++;
 if(after.branchAttempts>8)report.branchBudgetViolations++;
 if(!('bodyClaims' in after))throw Error('Qualified source observer lost fields on unknown input');
 for(const c of [...after.envelopeFields,...after.bodyClaims]){
   if(original.subarray(c.startByte,c.endByte).toString('utf8')!==c.rawSpanValue)
     report.replayByteDrift++;
 }
 const noProof=inspectIndependentLogfmt(raw);
 if(noProof.claims.length||noProof.autoPromoted)report.explicitFramingClaimsOnUnknown++;
 if(invalid){
   const old=before.disposition.startsWith('REVIEW_ONLY');
   const now=after.disposition.startsWith('REVIEW_ONLY');
   report.historicalMalformedReviewOld+=Number(old);
   report.historicalMalformedReviewNew+=Number(now);
   report.newMalformedReview+=Number(now&&!old);
   if(now){
     const veto=arbitrateOptionalIndependentLogfmt(raw,undefined,{
       sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'UNSCORED',
     });
     if(veto.disposition!=='ABSTAIN_UNSAFE'||veto.autoPromoted)
       report.independentVetoBypasses++;
   }
 }
 if(independent)report.previouslyIndependentNonLogfmt++;
}
for(const [directory,filename,expectedSha,expectedCount,invalid] of history){
 const blob=fs.readFileSync(path.join(state,directory,filename));
 if(sha(blob)!==expectedSha)throw Error('Historical original source SHA drift');
 const rows=JSON.parse(blob.toString('utf8')) as Array<{raw:string}>;
 if(rows.length!==expectedCount)throw Error('Historical source case denominator drift');
 for(const record of rows){
   if(invalid)report.historicalInvalidMutations++;else report.historicalOriginals++;
   verify(record.raw,invalid,false);
 }
}
for(const [directory,filename,digest,expectedCount,status] of previous){
 const blob=fs.readFileSync(path.join(state,directory,filename));
 if(sha(blob)!==digest)throw Error('Previous frozen independent original reference SHA drift');
 const rows=JSON.parse(blob.toString('utf8')) as Array<{raw:string;status:string}>;
 const selected=rows.filter(x=>x.status===status);
 if(selected.length!==expectedCount)throw Error('Previous independently qualified denominator drift');
 for(const record of selected)verify(record.raw,false,true);
}
console.log('INDEPENDENT_LOGFMT_SAFETY '+JSON.stringify({
 ...report,scope:'HISTORICAL_SAFETY_ONLY_NOT_RELABELED_NEW_ACCURACY',
 precedingSourceProductsUnchanged:true,rawAndNativeSuccessNotCertified:true,
}));
if(report.historicalOriginals!==1361||report.historicalInvalidMutations!==2892||
   report.previouslyIndependentNonLogfmt!==50||
   report.historicalMalformedReviewOld!==197||
   report.historicalMalformedReviewNew!==197||
   report.resultChanges||report.newMalformedReview||report.originalByteDrift||
   report.replayByteDrift||report.autoPromotions||report.branchBudgetViolations||
   report.independentVetoBypasses||report.explicitFramingClaimsOnUnknown)
 process.exitCode=1;
