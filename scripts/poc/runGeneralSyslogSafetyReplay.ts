/** Affected-stage-only replay of previously frozen foreign formats and invalid mutations.
 * Historical samples are NOT relabeled a fresh independent accuracy holdout.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';

type Row={id:string;source:string;raw:string};
const state=path.join(os.homedir(),'.local/state');
const vendor=path.join(state,'parserstudio-fresh-vendor-holdout-20261016');
const external=path.join(state,'parserstudio-ext-holdout-20261016');
const specs=[
  {label:'vendorOriginal',base:vendor,file:'records.json',count:571,
    sha:'3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',invalid:false},
  {label:'externalOriginal',base:external,file:'records.json',count:790,
    sha:'dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',invalid:false},
  {label:'vendorInvalid',base:vendor,file:'known_invalid.json',count:1,
    sha:'da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',invalid:true},
  {label:'externalInvalid',base:external,file:'adversarial.json',count:1532,
    sha:'9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',invalid:true},
  {label:'junosBareInvalid',base:vendor,file:'junos_bare_mutations.json',count:45,
    sha:'389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',invalid:true},
  {label:'junosBracketInvalid',base:vendor,file:'junos_bracket_mutations.json',count:414,
    sha:'5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',invalid:true},
  {label:'sophosInvalid',base:vendor,file:'sophos_kv_mutations.json',count:900,
    sha:'1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',invalid:true},
] as const;
const sha=(data:Buffer)=>crypto.createHash('sha256').update(data).digest('hex');
let knownOriginals=0,knownInvalidMutations=0,originalReviewOnly=0,
  invalidSyntaxReviewOnly=0,unsafeAbstentions=0,rawOnly=0;
let verifiedByteSpans=0,sourceByteDrift=0,autoPromotions=0,maxBranchAttempts=0;
const byCohort:Record<string,{events:number;reviewOnly:number;abstainUnsafe:number;rawOnly:number}>={};
for(const s of specs){
  const original=fs.readFileSync(path.join(s.base,s.file));
  if(sha(original)!==s.sha)throw Error('Frozen foreign source SHA changed');
  const rows=JSON.parse(original.toString('utf8')) as Row[];
  if(rows.length!==s.count)throw Error('Frozen foreign denominator changed');
  const group={events:0,reviewOnly:0,abstainUnsafe:0,rawOnly:0};
  for(const row of rows){
    const result=inspectGeneralSyslogEnvelope(row.raw);
    const rawBytes=new TextEncoder().encode(row.raw);
    group.events++;
    if(s.invalid)knownInvalidMutations++;else knownOriginals++;
    if(result.sourceBytes!==rawBytes.length||result.originalRaw!==row.raw)sourceByteDrift++;
    if(result.autoPromoted||result.nativeParser!=='NOT_VERIFIED')autoPromotions++;
    maxBranchAttempts=Math.max(maxBranchAttempts,result.branchAttempts);
    if(result.disposition==='REVIEW_ONLY'){
      group.reviewOnly++;
      if(s.invalid)invalidSyntaxReviewOnly++;else originalReviewOnly++;
    }else if(result.disposition==='ABSTAIN_UNSAFE'){
      group.abstainUnsafe++;unsafeAbstentions++;
      if(result.fields.length)throw Error('Unsafe outcome exposed source fields');
    }else{
      group.rawOnly++;rawOnly++;
      if(result.fields.length)throw Error('Unsupported format exposed source fields');
    }
    for(const span of result.fields){
      const slice=rawBytes.slice(span.startByte,span.endByte);
      if(new TextDecoder('utf-8',{fatal:true}).decode(slice)!==span.value)
        throw Error('Original UTF-8 byte replay mismatch');
      verifiedByteSpans++;
    }
  }
  byCohort[s.label]=group;
}
const result={knownOriginals,knownInvalidMutations,originalReviewOnly,
  invalidSyntaxReviewOnly,unsafeAbstentions,rawOnly,verifiedByteSpans,
  sourceByteDrift,autoPromotions,maxBranchAttempts,
  mutationStatus:'GRAMMAR_REVIEW_ONLY_NEVER_AUTO_PROMOTE',
  historicalAccuracyClaim:'NOT_RE_SCORED_AS_FRESH',
  byCohort};
console.log('SYSLOG_ENVELOPE_FOREIGN_FORMAT_SAFETY '+JSON.stringify(result));
if(knownOriginals!==1361||knownInvalidMutations!==2892||
   sourceByteDrift!==0||autoPromotions!==0||maxBranchAttempts>2)
  process.exitCode=1;
