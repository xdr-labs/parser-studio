/** Non-promoting new-logic replay over existing SHA-pinned negative controls.
 * This is an affected candidate safety check, not a fresh field accuracy test.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectBoundedSourceSpans} from '../../src/poc/boundedStructuralSourceSpans';

type Row={id:string;source:string;raw:string};
const root=path.join(os.homedir(),'.local/state');
const examples=[
  {label:'vendor_originals',dir:'parserstudio-fresh-vendor-holdout-20261016',file:'records.json',
    count:571,sha:'3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',negative:false},
  {label:'external_originals',dir:'parserstudio-ext-holdout-20261016',file:'records.json',
    count:790,sha:'dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',negative:false},
  {label:'known_invalid',dir:'parserstudio-fresh-vendor-holdout-20261016',file:'known_invalid.json',
    count:1,sha:'da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',negative:true},
  {label:'external_mutations',dir:'parserstudio-ext-holdout-20261016',file:'adversarial.json',
    count:1532,sha:'9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',negative:true},
  {label:'junos_bare_mutations',dir:'parserstudio-fresh-vendor-holdout-20261016',file:'junos_bare_mutations.json',
    count:45,sha:'389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',negative:true},
  {label:'junos_bracket_mutations',dir:'parserstudio-fresh-vendor-holdout-20261016',file:'junos_bracket_mutations.json',
    count:414,sha:'5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',negative:true},
  {label:'sophos_mutations',dir:'parserstudio-fresh-vendor-holdout-20261016',file:'sophos_kv_mutations.json',
    count:900,sha:'1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',negative:true},
] as const;
const sha=(v:Buffer|string)=>crypto.createHash('sha256').update(v).digest('hex');
let originals=0,invalid=0,reviewOriginals=0,reviewInvalid=0,unsafe=0,rawOnly=0;
let promoted=0,byteAccountingError=0;
const groups:Record<string,{samples:number;syntaxOnlyReview:number;unsafe:number;rawOnly:number}>={};
for(const spec of examples){
  const bytes=fs.readFileSync(path.join(root,spec.dir,spec.file));
  if(sha(bytes)!==spec.sha)throw Error('Frozen source SHA mismatch: '+spec.label);
  const rows=JSON.parse(bytes.toString('utf8')) as Row[];
  if(rows.length!==spec.count)throw Error('Frozen denominator mismatch: '+spec.label);
  const group={samples:0,syntaxOnlyReview:0,unsafe:0,rawOnly:0};
  for(const row of rows){
    const result=inspectBoundedSourceSpans(row.raw);
    group.samples++;
    if(spec.negative)invalid++;else originals++;
    if(result.autoPromoted||result.nativeVerified)promoted++;
    if(result.sourceBytes!==Buffer.byteLength(row.raw,'utf8'))byteAccountingError++;
    if(result.disposition==='REVIEW_ONLY'){
      group.syntaxOnlyReview++;
      if(spec.negative)reviewInvalid++;else reviewOriginals++;
    }else if(result.disposition==='ABSTAIN_UNSAFE'){
      group.unsafe++;unsafe++;
    }else{group.rawOnly++;rawOnly++;}
    if(result.fields.length&&result.disposition!=='REVIEW_ONLY')
      throw Error('Fields exposed for unqualified/unsafe source: '+spec.label);
  }
  groups[spec.label]=group;
}
if(originals!==1361||invalid!==2892||promoted!==0||byteAccountingError!==0)
  throw Error('New candidate changed frozen safety contract');
console.log('STRUCTURAL_GENERALIZATION_SAFETY '+JSON.stringify({
  frozenPreviouslyKnownOriginals:originals,frozenInvalidMutations:invalid,
  reviewOriginalsSyntaxOnly:reviewOriginals,reviewInvalidSyntaxOnly:reviewInvalid,
  unsafeAbstentions:unsafe,rawOnlyAbstentions:rawOnly,
  autoPromoted:promoted,byteAccountingError,
  invalidReviewStatus:'NOT_SOURCE_VERIFIED_NOT_FALSE_COMPLETE',
  originalFieldAccuracy:'NOT_RESCORED',
  groups,
}));
