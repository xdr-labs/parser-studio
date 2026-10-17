/** Pinned previously unused versioned Fortinet original KV source holdout. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {conservativeKvFields} from '../../src/poc/conservativeKvGrammar';
import {sourceKvReference,scoreKvFields} from '../../src/poc/syslogKvFieldFidelity';

type Proof={sha256:string;sourceFile:string;sourceGrammar:string;fields:unknown};
type Oracle={revision:string;accepted:Record<string,Proof>;unscorable:Record<string,string[]>};
type Score={fields:number;exact:number;fp:number;fn:number;exactEvents:number;noContract:number};
const blank=():Score=>({fields:0,exact:0,fp:0,fn:0,exactEvents:0,noContract:0});
const hash=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-conservative-escape-fresh-20261017');
const expectedFiles=[
 {filename:'test-fortinet-7-4.log',sha:'ef04aa4d229c924ee2a0fd44923cbe412392ea40a37b083ba756857d7a671d97',records:82,duplicates:0,qualified:47,fields:1491},
 {filename:'test-fortinet-6-2.log',sha:'6bc2d9721c7b386ce2c499ab3bb50e08845625b78ae0076730a02ca6929ed8e6',records:57,duplicates:28,qualified:17,fields:586},
 {filename:'test-fortinet-unsanitized.log',sha:'9d7aad944899837bd88872f8a7449d44c3b2816e4f7c0a1fc7900bca863a2108',records:2,duplicates:0,qualified:0,fields:0},
] as const;
const oracle=JSON.parse(fs.readFileSync(path.join(root,'oracle-versioned-fortinet-kv-physical.json'),'utf8')) as Oracle;
if(oracle.revision!=='ee918d03f4a90dacd32673546c64a633308796ef'||
  Object.keys(oracle.accepted).length!==64)
  throw Error('Frozen versioned original field oracle drifted');
const seen=new Set<string>();
const candidate=blank(),currentFortinet=blank(),currentGeneric=blank();
let sourceLines=0,duplicates=0,qualified=0,unscorable=0;
let unscorableCandidateAccepted=0,unscorableProductAccepted=0;
const byFile:Record<string,{records:number;qualified:number;fields:number;excluded:number}>={};
function absorb(target:Score,expected:ReadonlyMap<string,string>,values:unknown):void{
 const result=scoreKvFields(expected,values);
 target.fields+=result.expected;
 target.exact+=result.exact;
 target.fp+=result.wrongValue+result.unexpected;
 target.fn+=result.wrongValue+result.missing;
 if(result.exactEvent)target.exactEvents++;
 if(values===undefined||values===null)target.noContract++;
}
for(const file of expectedFiles){
 const bytes=fs.readFileSync(path.join(root,file.filename));
 if(hash(bytes)!==file.sha)throw Error('Versioned source file hash drifted');
 const lines=bytes.toString('utf8').replace(/^\uFEFF/,'').split(/\r\n|\n|\r/).filter(x=>x.trim());
 if(lines.length!==file.records)throw Error('Versioned source record count drifted');
 const skipped=new Set(oracle.unscorable[file.filename]??[]);
 const group={records:0,qualified:0,fields:0,excluded:0};
 let ignoredRepeats=0;
 for(const raw of lines){
  sourceLines++;
  const id=hash(raw);
  if(seen.has(id)){duplicates++;ignoredRepeats++;continue;}
  seen.add(id);
  group.records++;
  const proof=oracle.accepted[id];
  if(!proof){
   if(!skipped.has(id))throw Error('Unqualified versioned original was not explicitly scored out');
   unscorable++;group.excluded++;
   if(conservativeKvFields(raw)!==null)unscorableCandidateAccepted++;
   if(parseSecurityInput(raw).ok)unscorableProductAccepted++;
   continue;
  }
  if(proof.sha256!==id||proof.sourceFile!==file.filename)
   throw Error('Versioned independent original record association drifted');
  qualified++;group.qualified++;
  const reference=sourceKvReference(proof.fields);
  group.fields+=reference.size;
  const parsed=conservativeKvFields(raw);
  absorb(candidate,reference,parsed?.fields);
  const current=parseSecurityInput(raw);
  const event=current.ok&&current.events.length===1?current.events[0]:undefined;
  const fortinet=event?.fields?.fortinet as Record<string,unknown>|undefined;
  const generic=event?.fields?.generic as Record<string,unknown>|undefined;
  // Compare both FIXED product source contracts independently; never opportunistically
  // pick the better-looking path or union inferred mappings.
  absorb(currentFortinet,reference,fortinet?.fields);
  absorb(currentGeneric,reference,generic?.kv);
 }
 if(group.qualified!==file.qualified||group.fields!==file.fields||
   ignoredRepeats!==file.duplicates)
   throw Error('Versioned original independent group denominator drifted');
 byFile[file.filename]=group;
}
if(sourceLines!==141||duplicates!==28||seen.size!==113||qualified!==64||
   unscorable!==49||candidate.fields!==2077||currentFortinet.fields!==2077||
   currentGeneric.fields!==2077)
  throw Error('Pinned versioned source accounting invariant failed');
console.log('VERSIONED_FORTINET_CONSERVATIVE_KV_HOLDOUT '+JSON.stringify({
 upstreamPinnedRevision:oracle.revision,physicallyPresentLines:sourceLines,
 deduplicatedOriginalRecords:seen.size,repeatedOriginalsExcluded:duplicates,
 qualifiedOriginals:qualified,independentSourceFieldTokens:candidate.fields,
 sourceUnscorableOriginals:unscorable,
 conservativeCandidate:candidate,unchangedFortinetFixedContract:currentFortinet,
 unchangedGenericFixedContract:currentGeneric,
 candidateStructurallyAcceptedUnscorable:unscorableCandidateAccepted,
 currentProductStructurallyAcceptedUnscorable:unscorableProductAccepted,
 perSource:byFile,manufacturerSemantics:'NOT_VERIFIED',
 fullyIndependentRandomHoldout:false,nativeExecution:'NOT_VERIFIED',
 noAutomaticPromotion:true,privateOriginalValuesLogged:false,
}));
if(candidate.fp!==0||candidate.fn!==0)process.exitCode=1;
