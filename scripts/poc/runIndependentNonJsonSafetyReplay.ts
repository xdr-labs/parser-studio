/** Historic 1,361/2,892 safety replay ONLY, not a fresh accuracy claim. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateSourceBody} from '../../src/poc/boundedSourceBodyArbiter';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
const state=path.join(os.homedir(),'.local/state');
const sha=(b:Buffer)=>crypto.createHash('sha256').update(b).digest('hex');
const source=[
  ['parserstudio-fresh-vendor-holdout-20261016','records.json','3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',571,false],
  ['parserstudio-ext-holdout-20261016','records.json','dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',790,false],
  ['parserstudio-fresh-vendor-holdout-20261016','known_invalid.json','da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',1,true],
  ['parserstudio-ext-holdout-20261016','adversarial.json','9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',1532,true],
  ['parserstudio-fresh-vendor-holdout-20261016','junos_bare_mutations.json','389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',45,true],
  ['parserstudio-fresh-vendor-holdout-20261016','junos_bracket_mutations.json','5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',414,true],
  ['parserstudio-fresh-vendor-holdout-20261016','sophos_kv_mutations.json','1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',900,true],
] as const;
const report={originals:0,invalidMutations:0,newReviewOriginals:0,
  newReviewInvalids:0,newClaimOriginals:0,newClaimInvalids:0,
  previouslyReviewInvalids:0,candidateReviewInvalids:0,
  byteDrift:0,autoPromoted:0,branchesOver8:0,
  independentVetoEscape:0,utf8SpanDrift:0};
const group:Record<string,{originals:number;invalids:number;newReviewInvalids:number;newReviewOriginals:number}>={};
for(const [dir,file,digest,count,invalid] of source){
  const raw=fs.readFileSync(path.join(state,dir,file));
  if(sha(raw)!==digest)throw Error('Historical SHA drift');
  const events=JSON.parse(raw.toString('utf8')) as Array<{raw:string}>;
  if(events.length!==count)throw Error('Frozen source event count drift');
  const stat=group[dir+'/'+file]={originals:0,invalids:0,newReviewInvalids:0,newReviewOriginals:0};
  for(const event of events){
    if(invalid){report.invalidMutations++;stat.invalids++;}
    else{report.originals++;stat.originals++;}
    const old=arbitrateSourceBody(event.raw);
    const current=arbitrateIndependentNonJson(event.raw);
    const sourceRaw=Buffer.from(event.raw,'utf8');
    if(current.sourceBytes!==sourceRaw.length||current.raw!==event.raw)report.byteDrift++;
    if(current.autoPromoted||current.independentOracleCertified||current.nativeVerified)report.autoPromoted++;
    if(current.branchAttempts>8)report.branchesOver8++;
    const before=old.disposition.startsWith('REVIEW_ONLY');
    const after=current.disposition.startsWith('REVIEW_ONLY');
    if(invalid){
      report.previouslyReviewInvalids+=Number(before);
      report.candidateReviewInvalids+=Number(after);
      report.newReviewInvalids+=Number(!before&&after);
      stat.newReviewInvalids+=Number(!before&&after);
      report.newClaimInvalids+=Number(current.bodyClaims.length>0&&old.bodyClaims.length===0);
    }else{
      report.newReviewOriginals+=Number(!before&&after);
      stat.newReviewOriginals+=Number(!before&&after);
      report.newClaimOriginals+=Number(current.bodyClaims.length>0&&old.bodyClaims.length===0);
    }
    for(const claim of [...current.envelopeFields,...current.bodyClaims]){
      if(sourceRaw.subarray(claim.startByte,claim.endByte).toString('utf8')!==claim.rawSpanValue)
        report.utf8SpanDrift++;
    }
    if(invalid&&after){
      const veto=arbitrateIndependentNonJson(event.raw,{
        sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'UNSCORED'});
      if(veto.disposition!=='ABSTAIN_UNSAFE'||veto.bodyClaims.length||veto.autoPromoted)
        report.independentVetoEscape++;
    }
  }
}
console.log('INDEPENDENT_NONJSON_HISTORICAL '+JSON.stringify({
  ...report,groups:group,qualifier:'HISTORICAL_SAFETY_REPLAY_NOT_BLIND',
  newReviewInvalidsStatus:'UNVERIFIED_REVIEW_FALSE_POSITIVE_RISK_NOT_SOURCE_SUCCESS'}));
if(report.originals!==1361||report.invalidMutations!==2892||report.byteDrift||
  report.autoPromoted||report.branchesOver8||report.utf8SpanDrift||report.independentVetoEscape)
  process.exitCode=1;
