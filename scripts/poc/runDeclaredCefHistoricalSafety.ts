/** Exact historical replay: our new optional source observer must never
 * promote, classify or modify any unqualified upstream original or mutation.
 * These fixtures are HISTORICAL SAFETY ONLY, not a new blind accuracy holdout.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {arbitrateOptionalIndependentLogfmt} from '../../src/poc/independentLogfmtSource';
import {inspectDeclaredCefEscape} from '../../src/poc/declaredCefExtensionEscape';
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
let originals=0,invalid=0,lexicalReview=0,unqualifiedClaims=0,byteDrift=0,
 sourceSuccess=0,autoSuccess=0;
const buckets:Record<string,number>={};
for(const [directory,file,digest,count,malformed] of groups){
 const bytes=fs.readFileSync(path.join(base,directory,file));
 if(sha(bytes)!==digest)throw Error('Historical input SHA drift: '+file);
 const rows=JSON.parse(bytes.toString('utf8')) as Array<{raw:string}>;
 if(rows.length!==count)throw Error('Historical count drift: '+file);
 for(const {raw} of rows){
  if(malformed)invalid++;else originals++;
  const previous=arbitrateOptionalIndependentLogfmt(raw);
  const observer=inspectDeclaredCefEscape(raw); // NO QUALIFIED SOURCE CONTEXT
  if(malformed&&previous.disposition.startsWith('REVIEW_ONLY')){
   lexicalReview++;
   const key=file+'|'+previous.disposition;
   buckets[key]=(buckets[key]??0)+1;
  }
  unqualifiedClaims+=observer.fields.length;
  byteDrift+=Number(observer.raw!==raw||
    observer.sourceBytes!==Buffer.byteLength(raw,'utf8'));
  sourceSuccess+=Number(observer.disposition==='REVIEW_ONLY');
  autoSuccess+=Number(observer.autoPromoted||previous.autoPromoted||
    observer.nativeStellar!=='NOT_VERIFIED');
 }
}
const result={scope:'HISTORICAL_SAFETY_NOT_FRESH_INDEPENDENT_ACCURACY',originals,invalid,
 historicalLexicalReview:lexicalReview,
 priorReviewByGroup:buckets,
 changesToUnqualifiedSourceClaims:unqualifiedClaims,
 newSourceReviewsOnUnknown:sourceSuccess,
 autoOrNativeSuccessPromotions:autoSuccess,
 originalByteDrift:byteDrift,
 remaining171SophosAnd26EnvelopeNotAutoCorrected:true,
 originalLogsPrinted:false};
console.log('DECLARED_CEF_ESCAPE_HISTORICAL_SAFETY '+JSON.stringify(result));
if(originals!==1361||invalid!==2892||lexicalReview!==197||
 byteDrift||unqualifiedClaims||sourceSuccess||autoSuccess)process.exitCode=1;
