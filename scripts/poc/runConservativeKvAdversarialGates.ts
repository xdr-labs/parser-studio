/** Accuracy gate for NEW isolated KV candidate on previously frozen security holdouts.
 *  Does not requalify prior product parser or infer a source oracle from output.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {conservativeKvFields} from '../../src/poc/conservativeKvGrammar';
import {sourceKvReference,scoreKvFields} from '../../src/poc/syslogKvFieldFidelity';

type RecordInput={id:string;source:string;raw:string};
type Cohort={sha:string;records:number;file:string};
type Tally={events:number;lexerCandidates:number;lexicalCandidatesWithIndependentSourceOracle:number;
  exactSourceNameAndValues:number;sourceValueMismatch:number;sourceOracleNotMatched:number;
  oracleExpectedFields:number};
const make=():Tally=>({events:0,lexerCandidates:0,
  lexicalCandidatesWithIndependentSourceOracle:0,exactSourceNameAndValues:0,
  sourceValueMismatch:0,sourceOracleNotMatched:0,oracleExpectedFields:0});
const root=path.join(os.homedir(),'.local/state');
const vendor=path.join(root,'parserstudio-fresh-vendor-holdout-20261016');
const external=path.join(root,'parserstudio-ext-holdout-20261016');
const digest=(b:Buffer|string)=>crypto.createHash('sha256').update(b).digest('hex');
const readPinned=<T>(base:string,file:Cohort):T=>{
 const bytes=fs.readFileSync(path.join(base,file.file));
 if(digest(bytes)!==file.sha)throw Error('Frozen source or adversarial corpus SHA drift: '+file.file);
 const parsed=JSON.parse(bytes.toString('utf8')) as T;
 if(!Array.isArray(parsed)||parsed.length!==file.records)
  throw Error('Frozen source or adversarial denominator drift: '+file.file);
 return parsed;
};
const files={
 vendorRecords:{file:'records.json',records:571,sha:'3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2'},
 externalRecords:{file:'records.json',records:790,sha:'dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e'},
 vendorKnownInvalid:{file:'known_invalid.json',records:1,sha:'da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2'},
 externalMutations:{file:'adversarial.json',records:1532,sha:'9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c'},
 junosBareMutations:{file:'junos_bare_mutations.json',records:45,sha:'389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7'},
 junosBracketMutations:{file:'junos_bracket_mutations.json',records:414,sha:'5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166'},
 sophosMutations:{file:'sophos_kv_mutations.json',records:900,sha:'1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82'},
} as const;
const sampleGroups:Record<string,Tally>={};
const mutationGroups:Record<string,{tests:number;lexicalCandidates:number}>={};
const sophosOracle=JSON.parse(fs.readFileSync(path.join(vendor,'sophos_kv_oracle.json'),'utf8')) as
  {oracle:Record<string,Record<string,string>>;unscannable:string[]};
const junosOracle=JSON.parse(fs.readFileSync(path.join(vendor,'junos_bracket_oracle.json'),'utf8')) as
  {oracle:Record<string,Record<string,string>>;unscannable:string[]};
const junosBareOracle=JSON.parse(fs.readFileSync(path.join(vendor,'junos_bare_oracle.json'),'utf8')) as Record<string,Record<string,string>>;
if(Object.keys(sophosOracle.oracle).length!==151||sophosOracle.unscannable.length!==120||
   Object.keys(junosOracle.oracle).length!==69||Object.keys(junosBareOracle).length!==5)
 throw Error('Vendor independent source oracle count drifted');
let independentlyQualifiedMatches=0,oracleReferenceCandidates=0,oracleReferenceErrors=0;
function inspectPositive(row:RecordInput,cohort:string):void{
 if(typeof row.raw!=='string'||typeof row.source!=='string')
   throw Error('Frozen source record is malformed');
 const family=row.source.split('/').slice(0,2).join('/');
 const key=cohort+':'+family;
 const state=sampleGroups[key]??=make();
 state.events++;
 const outcome=conservativeKvFields(row.raw);
 if(outcome)state.lexerCandidates++;
 const ref=family==='sophos/xg'?sophosOracle.oracle[row.id]:undefined;
 if(ref){
   state.oracleExpectedFields+=Object.keys(ref).length;
   if(outcome){
     oracleReferenceCandidates++;
     state.lexicalCandidatesWithIndependentSourceOracle++;
     const source=sourceKvReference(Object.entries(ref));
     const check=scoreKvFields(source,outcome.fields);
     if(check.exactEvent){
       independentlyQualifiedMatches++;
       state.exactSourceNameAndValues++;
     }else{
       oracleReferenceErrors++;
       state.sourceValueMismatch++;
     }
   }else state.sourceOracleNotMatched++;
 }
}
function inspectNegatives(events:RecordInput[],kind:string):void{
 const entry={tests:events.length,lexicalCandidates:0};
 for(const row of events){
   if(typeof row.raw!=='string')throw Error('Frozen mutated input missing source');
   if(conservativeKvFields(row.raw))entry.lexicalCandidates++;
 }
 mutationGroups[kind]=entry;
}
const originals571=readPinned<RecordInput[]>(vendor,files.vendorRecords);
const originals790=readPinned<RecordInput[]>(external,files.externalRecords);
for(const row of originals571)inspectPositive(row,'vendor571');
for(const row of originals790)inspectPositive(row,'external790');
inspectNegatives(readPinned<RecordInput[]>(vendor,files.vendorKnownInvalid),'vendorKnownInvalid');
inspectNegatives(readPinned<RecordInput[]>(external,files.externalMutations),'external790Mutations');
inspectNegatives(readPinned<RecordInput[]>(vendor,files.junosBareMutations),'junosBareMutations');
inspectNegatives(readPinned<RecordInput[]>(vendor,files.junosBracketMutations),'junosBracketMutations');
inspectNegatives(readPinned<RecordInput[]>(vendor,files.sophosMutations),'sophosMutations');
const positiveScans=Object.values(sampleGroups);
const total=(key:keyof Tally)=>positiveScans.reduce((sum,v)=>sum+v[key],0);
const negatives=Object.values(mutationGroups);
const sumNegative=(key:'tests'|'lexicalCandidates')=>negatives.reduce((sum,v)=>sum+v[key],0);
if(total('events')!==1361||sumNegative('tests')!==2892||
   total('oracleExpectedFields')!==4956||total('lexerCandidates')!==254||
   oracleReferenceCandidates!==151||independentlyQualifiedMatches!==151||
   oracleReferenceErrors!==0||mutationGroups.sophosMutations?.lexicalCandidates!==600||
   sumNegative('lexicalCandidates')!==600)
 throw Error('Source/independent Oracle or adversarial candidate gate drifted');
console.log('CONSERVATIVE_KV_CANDIDATE_571_790_JUNOS_SOPHOS_AUDIT '+JSON.stringify({
  frozenOriginalSourceRecords:1361,sourceCohortCounts:{vendor571:571,external790:790},
  candidateLexicalEligibleOriginals:total('lexerCandidates'),
  independentSophosQualifiedSourceReferences:Object.keys(sophosOracle.oracle).length,
  candidateEligibleWithIndependentSophosReference:oracleReferenceCandidates,
  candidateExactAgainstIndependentSophosReference:independentlyQualifiedMatches,
  candidateDisagreesWithIndependentSophosSourceOracle:oracleReferenceErrors,
  priorJunosBracketSourceOracleCount:Object.keys(junosOracle.oracle).length,
  priorJunosBareSourceOracleCount:Object.keys(junosBareOracle).length,
  mutationOriginals:sumNegative('tests'),
  syntacticallyEligibleMutations:sumNegative('lexicalCandidates'),
  sampledByFamily:sampleGroups,mutationByCohort:mutationGroups,
  candidateGrammaticalRecognitionOnly:true,
  anyUnscoredResultPromoted:false,manufacturerSemanticsVerified:false,
  productionParserChanged:false,sourceRawOrFieldsPrinted:false,
}));
