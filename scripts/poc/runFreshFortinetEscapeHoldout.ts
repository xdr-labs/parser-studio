/** Third-party unseen escaped-source field exactness; never emits raw values. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {conservativeKvFields} from '../../src/poc/conservativeKvGrammar';
import {sourceKvReference,scoreKvFields} from '../../src/poc/syslogKvFieldFidelity';
import {parseSecurityInput} from '../../src/securityInputPipeline';

type Reference={sourceSha256:string;grammar:string;fields:unknown};
type Oracle={revision:string;sourceFileSHA256:string;expectedFileSHA256:string;
  qualified:Record<string,Reference>;unscorableSourceSHA256:string[]};
type Metrics={total:number;exact:number;wrong:number;missing:number;unexpected:number;
  exactEvents:number;noContract:number};
const empty=():Metrics=>({total:0,exact:0,wrong:0,missing:0,
  unexpected:0,exactEvents:0,noContract:0});
const sha=(data:string|Buffer)=>crypto.createHash('sha256').update(data).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-fortinet-escape-source-discovery-20261017');
const source='test-fortinet-fix.log';
const expected='test-fortinet-fix.log-expected.json';
const originalBytes=fs.readFileSync(path.join(root,source));
const expectedBytes=fs.readFileSync(path.join(root,expected));
const oracle=JSON.parse(fs.readFileSync(
  path.join(root,'oracle-fresh-fortinet-fix-escape-originals.json'),'utf8')) as Oracle;
if(sha(originalBytes)!=='4194fdcd7d83df764eadb04e436c3a23247405c8a5995a473f9a57290cb31cef'||
   sha(expectedBytes)!=='14c1d87ce96b764019c0acff98165f17a6c134487a9ec39cbdc1a41d4d0284ae'||
   oracle.revision!=='ee918d03f4a90dacd32673546c64a633308796ef'||
   oracle.sourceFileSHA256!==sha(originalBytes)||oracle.expectedFileSHA256!==sha(expectedBytes)||
   Object.keys(oracle.qualified).length!==3||oracle.unscorableSourceSHA256.length!==1)
  throw Error('Unseen escaped-value third-party original/independent Oracle SHA drift');
const parsedGolden=JSON.parse(expectedBytes.toString('utf8')) as Record<string,unknown>;
const expectedEvents=Object.values(parsedGolden).flat();
if(expectedEvents.length!==4)throw Error('Pinned golden expected events denominator mismatch');
const goldenHashes=new Set<string>();
for(const value of expectedEvents){
 const rec=(value as Record<string,unknown>).event as Record<string,unknown>|undefined;
 if(typeof rec?.original!=='string')throw Error('Expected upstream record has no original source');
 goldenHashes.add(sha(rec.original));
}
if(goldenHashes.size!==4)throw Error('Upstream expected raw hashes not unique');
const physical=originalBytes.toString('utf8').replace(/^\uFEFF/,'')
  .split(/\r\n|\r|\n/).filter(x=>x.trim());
if(physical.length!==4||new Set(physical).size!==4)
  throw Error('Unseen source physical record denominator mismatch');
const baselineVendor=empty(),baselineGeneric=empty(),candidate=empty();
const scoreInto=(field:Metrics,original:ReadonlyMap<string,string>,current:unknown)=>{
 const s=scoreKvFields(original,current);
 field.total+=s.expected;
 field.exact+=s.exact;
 field.wrong+=s.wrongValue;
 field.missing+=s.missing;
 field.unexpected+=s.unexpected;
 if(s.exactEvent)field.exactEvents++;
 if(current===undefined||current===null)field.noContract++;
};
const seen=new Set<string>();
let excluded=0,sourceQualifiedEscaped=0,escapedCandidateExact=0,
  escapedProductVendorExact=0,escapedProductGenericExact=0;
let currentAcceptedUnscorable=0,candidateAcceptedUnscorable=0;
for(const raw of physical){
 const id=sha(raw);
 if(!goldenHashes.has(id)||seen.has(id))throw Error('New source absent from upstream golden or duplicate');
 seen.add(id);
 const check=oracle.qualified[id];
 const proposed=conservativeKvFields(raw);
 const baseline=parseSecurityInput(raw);
 if(!check){
  if(!oracle.unscorableSourceSHA256.includes(id))
   throw Error('Unqualified source has no explicit independent abstention');
  excluded++;
  if(proposed)candidateAcceptedUnscorable++;
  if(baseline.ok)currentAcceptedUnscorable++;
  continue;
 }
 if(check.sourceSha256!==id)throw Error('Private frozen lexical reference source hash differs');
 const original=sourceKvReference(check.fields);
 const result=baseline.ok&&baseline.events.length===1?baseline.events[0]:undefined;
 const v=result?.fields?.fortinet as Record<string,unknown>|undefined;
 const g=result?.fields?.generic as Record<string,unknown>|undefined;
 const vendor=v?.fields as Record<string,unknown>|undefined;
 const generic=g?.kv as Record<string,unknown>|undefined;
 scoreInto(candidate,original,proposed?.fields);
 scoreInto(baselineVendor,original,vendor);
 scoreInto(baselineGeneric,original,generic);
 for(const [name,value] of original){
  if(!value.includes('\\'))continue;
  sourceQualifiedEscaped++;
  escapedCandidateExact+=proposed?.fields[name]===value?1:0;
  escapedProductVendorExact+=vendor?.[name]===value?1:0;
  escapedProductGenericExact+=generic?.[name]===value?1:0;
 }
}
if(seen.size!==4||excluded!==1||candidate.total!==125||
   sourceQualifiedEscaped!==1||baselineVendor.total!==125||baselineGeneric.total!==125)
 throw Error('Independent escaped-value holdout denominator drifted');
console.log('FRESH_FORTINET_ESCAPED_KV_HOLDOUT '+JSON.stringify({
  fixedUpstreamRevision:oracle.revision,sourceOriginals:4,
  upstreamExpectedSourceSHAAligned:goldenHashes.size,
  independentlyQualifiedOriginals:3,independentlyQualifiedKVFields:candidate.total,
  qualifiedSourceFieldsContainingBackslash:sourceQualifiedEscaped,
  candidate,unchangedProductFortinetContract:baselineVendor,
  unchangedProductGenericContract:baselineGeneric,
  qualifiedEscapedCandidateSourceExact:escapedCandidateExact,
  qualifiedEscapedProductFortinetSourceExact:escapedProductVendorExact,
  qualifiedEscapedProductGenericSourceExact:escapedProductGenericExact,
  sourceUnscorableOriginals:excluded,
  candidateStructurallyAcceptedUnscorable: candidateAcceptedUnscorable,
  unchangedProductStructurallyAcceptedUnscorable: currentAcceptedUnscorable,
  upstreamVendorSchemaMatchesQualifiedEscapedKey:false,
  manufacturerSemantics:'NOT_CERTIFIED',nativeApproved:false,
  qualifiedOriginalValuesPrinted:false,productIntegration:false,
}));
if(candidate.wrong||candidate.missing||candidate.unexpected)process.exitCode=1;
