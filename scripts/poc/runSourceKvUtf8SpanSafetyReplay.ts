/** Read-only affected-span-observer regression on previously frozen foreign formats.
 * Replays only the NEW byte-span observer parity, not earlier product/parser PoCs.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {conservativeKvFields} from '../../src/poc/conservativeKvGrammar';
import {conservativeKvLocatedFields} from '../../src/poc/conservativeKvUtf8Span';
import {classifyVendorSourceReview} from '../../src/poc/vendorProfileReviewGate';

type Row={id:string;source:string;raw:string};
const state=path.join(os.homedir(),'.local/state');
const vendor=path.join(state,'parserstudio-fresh-vendor-holdout-20261016');
const ext=path.join(state,'parserstudio-ext-holdout-20261016');
const specs=[
  {id:'vendorOriginals',base:vendor,file:'records.json',expected:571,
    sha:'3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',positive:true},
  {id:'externalOriginals',base:ext,file:'records.json',expected:790,
    sha:'dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',positive:true},
  {id:'vendorKnownInvalid',base:vendor,file:'known_invalid.json',expected:1,
    sha:'da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',positive:false},
  {id:'externalMutations',base:ext,file:'adversarial.json',expected:1532,
    sha:'9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',positive:false},
  {id:'junosBareMutations',base:vendor,file:'junos_bare_mutations.json',expected:45,
    sha:'389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',positive:false},
  {id:'junosBracketMutations',base:vendor,file:'junos_bracket_mutations.json',expected:414,
    sha:'5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',positive:false},
  {id:'sophosMutations',base:vendor,file:'sophos_kv_mutations.json',expected:900,
    sha:'1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',positive:false},
] as const;
const sha=(data:Buffer)=>crypto.createHash('sha256').update(data).digest('hex');
const counts:Record<string,{originals:number;mutations:number;lexicalCandidates:number;
  byteSpanCandidates:number;foreignFormatNoCandidate:number;mutationVeto:number}>={};
let originals=0,mutations=0,byteSpanOriginals=0,byteSpanMutations=0,
  falseNewCandidates=0,mutationsVeto=0;
for(const spec of specs){
  const bytes=fs.readFileSync(path.join(spec.base,spec.file));
  if(sha(bytes)!==spec.sha)throw Error('Frozen source or mutation SHA drift');
  const rows=JSON.parse(bytes.toString('utf8')) as Row[];
  if(rows.length!==spec.expected)throw Error('Frozen original/mutation denominator drift');
  const c={originals:0,mutations:0,lexicalCandidates:0,
    byteSpanCandidates:0,foreignFormatNoCandidate:0,mutationVeto:0};
  for(const row of rows){
    const source=conservativeKvFields(row.raw);
    const withBytes=conservativeKvLocatedFields(row.raw);
    if(!!source!==!!withBytes)falseNewCandidates++;
    if(source)c.lexicalCandidates++;
    if(withBytes)c.byteSpanCandidates++;
    if(spec.positive){
      originals++;c.originals++;
      if(withBytes)byteSpanOriginals++;
      else c.foreignFormatNoCandidate++;
    }else{
      mutations++;c.mutations++;
      if(withBytes)byteSpanMutations++;
      const result=classifyVendorSourceReview({
        lexicalCandidate:!!withBytes,
        originalSourceShaMatches:true,exactRawRetained:true,
        independentSourceVerdict:'UNSCORED',
        existingVendorProfile:'FAIL',
      });
      if(result.disposition==='EXISTING_VENDOR_PROFILE_VETO'){
        c.mutationVeto++;mutationsVeto++;
      }
      if(result.canAutoPromote||result.originalSourceVerified)
        throw Error('Unscored adversarial mutation auto-promoted');
    }
  }
  counts[spec.id]=c;
}
if(originals!==1361||mutations!==2892||byteSpanOriginals!==254||
   byteSpanMutations!==600||mutationsVeto!==600||falseNewCandidates!==0||
   counts.sophosMutations?.mutationVeto!==600||
   counts.externalOriginals?.byteSpanCandidates!==0||
   counts.junosBracketMutations?.byteSpanCandidates!==0||
   counts.junosBareMutations?.byteSpanCandidates!==0)
  throw Error('Changed span-observer cross-format safety regression');
console.log('SOURCE_KV_UTF8_SPAN_FOREIGN_FORMAT_ADVERSARIAL_PARITY '+JSON.stringify({
  frozenForeignOriginals:originals,previousKvCandidateOriginals:byteSpanOriginals,
  frozenAdversarialMutations:mutations,
  unscoredLexicalMutations:byteSpanMutations,
  invalidMutationVeto:mutationsVeto,observerNewFalseCandidates:falseNewCandidates,
  byCohort:counts,sourceFieldValuesPrinted:false,manufacturerCertified:false,
  productParserChanged:false,noAutoPromote:true,
}));
