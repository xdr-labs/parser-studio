/** Proves a generic KV match is NOT vendor readiness on frozen Sophos originals/mutations. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {sourceKvReference,scoreKvFields} from '../../src/poc/syslogKvFieldFidelity';
import {conservativeKvFields} from '../../src/poc/conservativeKvGrammar';
import {classifyVendorSourceReview,type VendorReviewDisposition} from '../../src/poc/vendorProfileReviewGate';

type Item={id:string;source?:string;raw:string};
type SourceExpected={oracle:Record<string,Record<string,string>>;unscannable:string[]};
const root=path.join(os.homedir(),'.local/state/parserstudio-fresh-vendor-holdout-20261016');
const sha=(raw:Buffer|string)=>crypto.createHash('sha256').update(raw).digest('hex');
const read=<T>(file:string,wantSha:string):T=>{
 const raw=fs.readFileSync(path.join(root,file));
 if(sha(raw)!==wantSha)throw Error('Frozen original/mutated source or oracle SHA drift');
 return JSON.parse(raw.toString('utf8')) as T;
};
const records=read<Item[]>('records.json','3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2');
const source=read<SourceExpected>('sophos_kv_oracle.json','b1ebbc634268050a276fe3af1e478652cfdb71a88b4e0c2d14cae5114210f3fb');
const mutated=read<Item[]>('sophos_kv_mutations.json','1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82');
if(records.length!==571||mutated.length!==900||
   Object.keys(source.oracle).length!==151||source.unscannable.length!==120)
 throw Error('Original independent Sophos corpus cardinality drift');
const originalOutcomes:Record<string,number>={},negativeOutcomes:Record<string,number>={};
const add=(outcomes:Record<string,number>,status:VendorReviewDisposition)=>{
 outcomes[status]=(outcomes[status]??0)+1;
};
let originals=0,lexicalPositives=0,eligibleReference=0,exactOriginalFields=0,
    candidateOriginalValueMismatches=0,existingProfileSourced=0;
for(const row of records.filter(x=>x.source?.startsWith('sophos/xg/'))){
 originals++;
 const extraction=conservativeKvFields(row.raw);
 if(extraction)lexicalPositives++;
 const originalReference=source.oracle[row.id];
 if(originalReference)eligibleReference++;
 const proof=originalReference?
   scoreKvFields(sourceKvReference(Object.entries(originalReference)),extraction?.fields):null;
 if(originalReference&&proof?.exactEvent)exactOriginalFields++;
 if(originalReference&&extraction&&!proof?.exactEvent)candidateOriginalValueMismatches++;
 const parsed=parseSecurityInput(row.raw);
 const event=parsed.ok&&parsed.events.length===1?parsed.events[0]:undefined;
 const sophos=event?.fields.sophos as Record<string,unknown>|undefined;
 const hasSourceSpecificProfile=!!sophos?.fields&&typeof sophos.fields==='object';
 if(hasSourceSpecificProfile)existingProfileSourced++;
 const verdict=classifyVendorSourceReview({
  lexicalCandidate:!!extraction,
  originalSourceShaMatches:true, // Pinned entire 571 file SHA validated above.
  exactRawRetained:!!parsed.ok&&parsed.source_raw===row.raw&&event?.raw===row.raw,
  independentSourceVerdict:originalReference?(proof?.exactEvent?'EXACT':'MISMATCH'):'UNSCORED',
  existingVendorProfile:hasSourceSpecificProfile?'PASS':'FAIL',
 });
 if(verdict.canAutoPromote)throw Error('Candidate auto-promotion forbidden');
 add(originalOutcomes,verdict.disposition);
}
let mutationLexical=0,mutationProfileSource=0,mutationVeto=0;
for(const invalid of mutated){
 const extraction=conservativeKvFields(invalid.raw);
 if(extraction)mutationLexical++;
 const parsed=parseSecurityInput(invalid.raw);
 const event=parsed.ok&&parsed.events.length===1?parsed.events[0]:undefined;
 const vendor=event?.fields.sophos as Record<string,unknown>|undefined;
 const profile=!!vendor?.fields&&typeof vendor.fields==='object';
 if(profile)mutationProfileSource++;
 const verdict=classifyVendorSourceReview({
  lexicalCandidate:!!extraction,originalSourceShaMatches:true,
  exactRawRetained:true,independentSourceVerdict:'UNSCORED',
  existingVendorProfile:profile?'PASS':'FAIL',
 });
 if(verdict.disposition==='EXISTING_VENDOR_PROFILE_VETO')mutationVeto++;
 if(verdict.originalSourceVerified||verdict.canAutoPromote)
   throw Error('Invalid mutation incorrectly considered source exact');
 add(negativeOutcomes,verdict.disposition);
}
if(originals!==271||lexicalPositives!==254||eligibleReference!==151||
   exactOriginalFields!==151||candidateOriginalValueMismatches!==0||
   existingProfileSourced!==150||
   originalOutcomes.SOURCE_EXACT_PROFILE_REVIEW_ONLY!==150||
   originalOutcomes.EXISTING_VENDOR_PROFILE_VETO!==104||
   originalOutcomes.NOT_KV_CANDIDATE!==17||
   mutationLexical!==600||mutationProfileSource!==0||mutationVeto!==600||
   negativeOutcomes.EXISTING_VENDOR_PROFILE_VETO!==600||
   negativeOutcomes.NOT_KV_CANDIDATE!==300)
 throw Error('Frozen Sophos source/profile independent safety accounting drifted');
console.log('SOPHOS_KV_LEXICAL_VS_VENDOR_REVIEW_GUARD '+JSON.stringify({
  totalOriginalSophos:originals,lexicallyEligibleOriginals:lexicalPositives,
  originalWithIndependentOracle:eligibleReference,
  originalExactSourceOracleCompared:exactOriginalFields,
  originalGenericCandidateFieldMismatches:candidateOriginalValueMismatches,
  originalExistingSourceSpecificVendorProfile:existingProfileSourced,
  malformedMutations:mutated.length,
  malformedLexicallyEligible:mutationLexical,
  malformedExistingVendorProfileAccepted:mutationProfileSource,
  malformedKVGrammarCandidatesVetoedByVendorProfile:mutationVeto,
  originalReviewDisposition:originalOutcomes,
  mutatedReviewDisposition:negativeOutcomes,
  priorProductParserUnchanged:true,manufacturerSemanticsApproved:false,
  noAutomatedPromotion:true,noOriginalRawFieldValuesEmitted:true,
}));
