/** New arbiter affected-stage replay of PREVIOUS frozen independent evidence.
 *
 * No event in this runner is relabeled a new blind holdout. Private originals
 * and expected values never leave the machine; print counters and hashes only.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateSourceBody} from '../../src/poc/boundedSourceBodyArbiter';

const root=path.join(os.homedir(),'.local/state');
const sha=(v:Buffer|string)=>crypto.createHash('sha256').update(v).digest('hex');
const groups=[
  {id:'vendor',dir:'parserstudio-fresh-vendor-holdout-20261016',
    file:'records.json',sha:'3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2',
    count:571,invalid:false},
  {id:'external',dir:'parserstudio-ext-holdout-20261016',
    file:'records.json',sha:'dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e',
    count:790,invalid:false},
  {id:'invalidKnown',dir:'parserstudio-fresh-vendor-holdout-20261016',
    file:'known_invalid.json',sha:'da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',
    count:1,invalid:true},
  {id:'adverse',dir:'parserstudio-ext-holdout-20261016',
    file:'adversarial.json',sha:'9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',count:1532,invalid:true},
  {id:'junosBare',dir:'parserstudio-fresh-vendor-holdout-20261016',
    file:'junos_bare_mutations.json',
    sha:'389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',
    count:45,invalid:true},
  {id:'junosBracket',dir:'parserstudio-fresh-vendor-holdout-20261016',
    file:'junos_bracket_mutations.json',
    sha:'5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',count:414,invalid:true},
  {id:'sophos',dir:'parserstudio-fresh-vendor-holdout-20261016',
    file:'sophos_kv_mutations.json',
    sha:'1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',
    count:900,invalid:true},
] as const;
const EXPECTED={original:1361,invalid:2892};
let original=0,invalid=0,byteDrift=0,unsafeSuccess=0,attemptsOver=0,
    reviewedOriginal=0,reviewedInvalid=0,bodyCandidatesOriginal=0,
    bodyCandidatesInvalid=0,invalidAbstained=0,rawOnly=0,totalClaims=0,
    explicitVetoDowngrades=0,invalidVetoEscape=0;
const cohorts:Record<string,{count:number;reviewed:number;structuredBody:number;abstain:number}>={};
for(const info of groups){
  const bytes=fs.readFileSync(path.join(root,info.dir,info.file));
  const expected=info.sha;
  if(sha(bytes)!==expected)throw Error('Pinned historical regression SHA drift: '+info.id);
  const rows=JSON.parse(bytes.toString('utf8')) as Array<{raw:string}>;
  if(rows.length!==info.count)throw Error('Historical frozen source count changed');
  const each={count:0,reviewed:0,structuredBody:0,abstain:0};
  for(const row of rows){
    each.count++;
    const proposed=arbitrateSourceBody(row.raw);
    if(info.invalid)invalid++;else original++;
    const actual=Buffer.from(row.raw,'utf8');
    if(proposed.raw!==row.raw||proposed.sourceBytes!==actual.length)byteDrift++;
    if(proposed.autoPromoted||proposed.nativeVerified||proposed.independentOracleCertified)
      unsafeSuccess++;
    if(proposed.branchAttempts>8)attemptsOver++;
    const review=proposed.disposition.startsWith('REVIEW_ONLY');
    if(review){
      each.reviewed++;
      if(info.invalid){
        reviewedInvalid++;
        // The independent negative test is a supplied profile veto, not a
        // newly discovered parser finding. Never claim it as new blind TP.
        const afterVeto=arbitrateSourceBody(row.raw,{
          sourceIdentity:'MATCH',structuralProfile:'VETO',
          independentSourceTruth:'UNSCORED',
        });
        if(afterVeto.disposition==='ABSTAIN_UNSAFE'&&
           afterVeto.bodyClaims.length===0&&!afterVeto.autoPromoted)
          explicitVetoDowngrades++;
        else invalidVetoEscape++;
      }else reviewedOriginal++;
    }
    const body=proposed.bodyClaims.length>0;
    if(body){
      each.structuredBody++;
      if(info.invalid)bodyCandidatesInvalid++;else bodyCandidatesOriginal++;
    }
    if(proposed.disposition==='ABSTAIN_UNSAFE'){
      each.abstain++;
      if(info.invalid)invalidAbstained++;
    }
    if(proposed.disposition==='RAW_ONLY')rawOnly++;
    for(const claim of [...proposed.envelopeFields,...proposed.bodyClaims]){
      totalClaims++;
      const slice=actual.subarray(claim.startByte,claim.endByte).toString('utf8');
      if(slice!==claim.rawSpanValue)byteDrift++;
    }
  }
  cohorts[info.id]=each;
}
if(original!==EXPECTED.original||invalid!==EXPECTED.invalid||byteDrift!==0||
   unsafeSuccess!==0||attemptsOver!==0||invalidVetoEscape!==0||
   explicitVetoDowngrades!==reviewedInvalid)
  throw Error('Bounded body arbitration violates existing safety baseline');
console.log('BOUNDED_ARBITER_HISTORICAL_SAFETY '+JSON.stringify({
  original,invalid,byteDrift,unsafeSuccess,attemptsOver,reviewedOriginal,
  reviewedInvalid,bodyCandidatesOriginal,bodyCandidatesInvalid,
  invalidAbstained,rawOnly,totalClaims,explicitVetoDowngrades,invalidVetoEscape,cohorts,
  scope:'AFFECTED_STAGE_SAFETY_REPLAY_NOT_FRESH_ACCURACY',
  invalidStatus:'REVIEW_ONLY_NEVER_SOURCE_VERIFIED',
}));

const jsonDir=path.join(root,'parserstudio-generalization-blind-20261017');
const meta=JSON.parse(fs.readFileSync(path.join(jsonDir,'oracle-summary.pinned.json'),'utf8'));
const jsonBytes=fs.readFileSync(path.join(jsonDir,'frozen-records-and-oracle.json'));
if(sha(jsonBytes)!==meta.private_oracle_sha256)throw Error('Frozen independent JSON oracle changed');
const jsonEvents=JSON.parse(jsonBytes.toString('utf8')) as Array<{
  raw:string|null;raw_event_sha256:string;oracle_status:string;
  fields:Array<{path:string;value:unknown;type:string;value_start_byte:number;value_end_byte:number}>;
}>;
let scorable=0,referenceFields=0,tp=0,fp=0,fn=0,exact=0,
    abstain=0,unscorable=0,jsonAutoPromotions=0;
for(const event of jsonEvents){
  if(event.raw===null)continue;
  if(sha(Buffer.from(event.raw,'utf8'))!==event.raw_event_sha256)
    throw Error('JSON source record drift');
  const result=arbitrateSourceBody(event.raw);
  jsonAutoPromotions+=Number(result.autoPromoted);
  if(event.oracle_status!=='INDEPENDENT_JSON_BYTE_TRUTH'){
    unscorable++;continue;
  }
  scorable++;referenceFields+=event.fields.length;
  if(result.disposition!=='REVIEW_ONLY_UNFRAMED')abstain++;
  let perfect=true;
  const found=new Map(result.bodyClaims.map(f=>[f.path.slice('/body'.length),f]));
  for(const expected of event.fields){
    const actual=found.get(expected.path);
    if(!actual){fn++;perfect=false;continue;}
    if(actual.valueType===expected.type&&Object.is(actual.value,expected.value)&&
      actual.startByte===expected.value_start_byte&&actual.endByte===expected.value_end_byte)
      tp++;
    else{fp++;fn++;perfect=false;}
  }
  for(const key of found.keys())
    if(!event.fields.some(f=>f.path===key)){fp++;perfect=false;}
  exact+=Number(perfect&&found.size===event.fields.length&&result.disposition==='REVIEW_ONLY_UNFRAMED');
}
console.log('BOUNDED_ARBITER_EXISTING_JSON_ORACLE '+JSON.stringify({
  scorable,referenceFields,tp,fp,fn,exact,abstain,unscorable,
  autoPromotions:jsonAutoPromotions,
  claim:'EXISTING_FROZEN_JSON_ORACLE_REGRESSION_NOT_NEW_BLIND',
}));
if(scorable!==588||referenceFields!==15655||tp!==referenceFields||
   fp!==0||fn!==0||exact!==588||jsonAutoPromotions!==0)
  process.exitCode=1;
