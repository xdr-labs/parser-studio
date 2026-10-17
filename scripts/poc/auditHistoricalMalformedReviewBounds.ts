/** Offline aggregate-only triage; historical invalid mutations are not fresh goldens. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateOptionalIndependentLogfmt} from '../../src/poc/independentLogfmtSource';
const S=path.join(os.homedir(),'.local/state');
const sets=[
 ['parserstudio-fresh-vendor-holdout-20261016','known_invalid.json','da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',1],
 ['parserstudio-ext-holdout-20261016','adversarial.json','9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',1532],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bare_mutations.json','389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',45],
 ['parserstudio-fresh-vendor-holdout-20261016','junos_bracket_mutations.json','5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',414],
 ['parserstudio-fresh-vendor-holdout-20261016','sophos_kv_mutations.json','1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',900],
] as const;
const sha=(x:Buffer)=>crypto.createHash('sha256').update(x).digest('hex');
const data:Record<string,Record<string,number>>={};
const shapes:Record<string,number>={};
let all=0,review=0;
for(const [directory,filename,digest,count] of sets){
 const blob=fs.readFileSync(path.join(S,directory,filename));
 if(sha(blob)!==digest)throw Error('Original historical corpus SHA changed');
 const rows=JSON.parse(blob.toString('utf8')) as Array<{raw:string}>;
 if(rows.length!==count)throw Error('Expected fixed historical count changed');
 const stats:Record<string,number>={};data[filename]=stats;
 for(const {raw} of rows){
  all++;
  const found=arbitrateOptionalIndependentLogfmt(raw);
  const key=found.disposition+'|'+found.envelopeMode+'|'+found.selectedBodyGrammar+
   '|'+found.bodyReviewEvidence;
  stats[key]=(stats[key]??0)+1;
  if(found.disposition.startsWith('REVIEW_ONLY')){
   review++;
   const syntactic = [
    raw.startsWith('<')?'pri':'no-pri',
    raw.includes('\\')?'backslash':'no-backslash',
    raw.includes('"')?'quote':'no-quote',
    /(?:^|\s)[a-z_][\w.-]*=\s/i.test(raw)?'empty_assign':'no_empty_assign',
    raw.includes('\n')||raw.includes('\r')?'multiline':'singleline',
    found.bodyClaims.length>0?'claims':'header_only',
   ].join('|');
   shapes[syntactic]=(shapes[syntactic]??0)+1;
  }
 }
}
console.log('HISTORICAL_MUTATIONS_ONLY '+JSON.stringify({total:all,review,
 cohorts:data,reviewSyntaxShapes:shapes,
 rawOriginalsOrValuesPrinted:false,independentSourceScored:false}));
if(all!==2892||review!==197)process.exitCode=1;
