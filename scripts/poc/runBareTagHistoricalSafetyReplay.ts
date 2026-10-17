/** Previously frozen originals/malformed mutations are safety-only, never accuracy goldens.
 * New optional observer must not turn the historical 197 lexical REVIEW_ONLY
 * proposals into source/native success without independent publisher framing.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {arbitrateOptionalIndependentLogfmt} from '../../src/poc/independentLogfmtSource';
import {inspectPublisherQualifiedBareTag} from '../../src/poc/publisherQualifiedBareTag';
const base=path.join(os.homedir(),'.local/state');
const groups=[
 ['parserstudio-fresh-vendor-holdout-20261016','records.json','3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',571,false],
 ['parserstudio-ext-holdout-20261016','records.json','dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',790,false],
 ['parserstudio-fresh-vendor-holdout-20261016','known_invalid.json','da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',1,true],
 ['parserstudio-ext-holdout-20261016','adversarial.json','9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',1532,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bare_mutations.json','389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',45,true],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bracket_mutations.json','5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',414,true],
 ['parserstudio-fresh-vendor-holdout-20261016','sophos_kv_mutations.json','1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',900,true],
] as const;
const sha=(b:Buffer)=>crypto.createHash('sha256').update(b).digest('hex');
const result={scope:'HISTORICAL_SAFETY_ONLY',originals:0,mutatedInvalid:0,
 previousLexicalReview:0,newUnknownReviews:0,
 newlyClaimedFields:0,rawByteDrift:0,autoOrNativePromotions:0};
for(const [directory,name,expectedSha,expectedCount,invalid] of groups){
 const data=fs.readFileSync(path.join(base,directory,name));
 if(sha(data)!==expectedSha)throw new Error('Pinned historical safety source drift');
 const rows=JSON.parse(data.toString('utf8')) as Array<{raw:string}>;
 if(rows.length!==expectedCount)throw new Error('Historical record count drift');
 for(const {raw} of rows){
  if(invalid)result.mutatedInvalid++;else result.originals++;
  const before=arbitrateOptionalIndependentLogfmt(raw);
  const newCandidate=inspectPublisherQualifiedBareTag(raw);
  if(invalid&&before.disposition.startsWith('REVIEW_ONLY'))
   result.previousLexicalReview++;
  result.newUnknownReviews+=Number(newCandidate.disposition==='REVIEW_ONLY');
  result.newlyClaimedFields+=newCandidate.fields.length;
  result.rawByteDrift+=Number(newCandidate.originalRaw!==raw||
   newCandidate.sourceBytes!==Buffer.byteLength(raw,'utf8'));
  result.autoOrNativePromotions+=Number(newCandidate.autoPromoted||
   newCandidate.nativeParser!=='NOT_VERIFIED');
 }
}
console.log('BARE_TAG_HISTORICAL_SAFETY '+JSON.stringify({...result,
 independentAccuracy:false,review197Unresolved:true,rawEventsPrinted:false}));
if(result.originals!==1361||result.mutatedInvalid!==2892||
 result.previousLexicalReview!==197||result.newUnknownReviews||
 result.newlyClaimedFields||result.rawByteDrift||result.autoOrNativePromotions)
 process.exitCode=1;
