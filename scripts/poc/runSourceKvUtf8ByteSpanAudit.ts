/** Read-only original KV byte-range comparison and targeted invalid mutation controls.
 * No original source, source field name, decoded value, or private reference emitted.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {conservativeKvFields} from '../../src/poc/conservativeKvGrammar';
import {conservativeKvLocatedFields} from '../../src/poc/conservativeKvUtf8Span';
import {judgeSourceKvSpans,type IndependentSourceSpan}
  from '../../src/poc/sourceKvSpanReviewGate';
import {classifyVendorSourceReview} from '../../src/poc/vendorProfileReviewGate';
import {parseSecurityInput} from '../../src/securityInputPipeline';

type SourceRow={id:string;source:string;raw:string};
type SpanEvidence={sourceSha256:string;status:string;sourceBytes?:number;
  fields?:IndependentSourceSpan[]};
type Oracle={schemaVersion:number;frozenCorpusSha256:string;
  records:Record<string,SpanEvidence>;counts:Record<string,number>};
const root=path.join(os.homedir(),'.local/state');
const previous=path.join(root,'parserstudio-lossless-blind-20261017');
const privateDir=path.join(root,'parserstudio-source-kv-byte-span-20261017');
const vendor=path.join(root,'parserstudio-fresh-vendor-holdout-20261016');
const sha=(v:string|Buffer)=>crypto.createHash('sha256').update(v).digest('hex');
const fixed={
  originals:'153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32',
  invalidSophos:'1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',
};
const privateOracle=path.join(privateDir,'source-kv-utf8-byte-span-oracle.json');
if(fs.statSync(privateOracle).mode&0o077)throw Error('Private Oracle is not mode 0600');
const reference=JSON.parse(fs.readFileSync(privateOracle,'utf8')) as Oracle;
if(reference.schemaVersion!==1||reference.frozenCorpusSha256!==fixed.originals||
   Object.keys(reference.records).length!==185)
  throw Error('Oracle schema, frozen SHA or event count drift');
const frozenBytes=fs.readFileSync(path.join(previous,'records.json'));
if(sha(frozenBytes)!==fixed.originals)throw Error('Frozen originals changed');
const originals=JSON.parse(frozenBytes.toString('utf8')) as SourceRow[];
if(originals.length!==222)throw Error('Frozen original records count changed');
let events=0,fields=0,exactEvents=0,exactFields=0;
let falsePositive=0,falseNegative=0,spanMismatch=0,valueMismatch=0;
let sourceUnscorable=0,candidateRejected=0,sourceIdentityErrors=0,bytesRetained=0;
const byFamily:Record<string,{events:number;fields:number;exactEvents:number;exactFields:number}>={};
const identities=new Set<string>();
for(const row of originals){
  const expected=reference.records[row.id];
  if(!expected)continue;
  const bytes=Buffer.from(row.raw,'utf8');
  const hash=sha(bytes);
  if(identities.has(hash))throw Error('Same event appears more than once');
  identities.add(hash);
  events++;
  const identityOk=hash===expected.sourceSha256&&bytes.length===expected.sourceBytes;
  if(!identityOk)sourceIdentityErrors++;
  const actual=conservativeKvLocatedFields(row.raw);
  if(!actual)candidateRejected++;
  const decision=judgeSourceKvSpans({
    sourceShaMatches:identityOk,exactRawRetained:sha(row.raw)===hash,
    expected:expected.fields??null,actual:actual?.spans??null,
  });
  if(decision.canAutoPromote)throw Error('Source proof must not promote into product');
  if(decision.disposition==='UNSCORABLE_SOURCE')sourceUnscorable++;
  const group=byFamily[row.source.split('/')[1]!]??=
    {events:0,fields:0,exactEvents:0,exactFields:0};
  group.events++;
  group.fields+=expected.fields?.length??0;
  group.exactFields+=decision.exactOriginalFields;
  fields+=expected.fields?.length??0;
  exactFields+=decision.exactOriginalFields;
  falsePositive+=decision.falsePositiveFields;
  falseNegative+=decision.falseNegativeFields;
  spanMismatch+=decision.spanMismatches;
  valueMismatch+=decision.valueMismatches;
  bytesRetained+=identityOk?bytes.length:0;
  if(decision.disposition==='REVIEW_ONLY_SOURCE_EXACT'){
    exactEvents++;
    group.exactEvents++;
  }
}
const mutationBytes=fs.readFileSync(path.join(vendor,'sophos_kv_mutations.json'));
if(sha(mutationBytes)!==fixed.invalidSophos)
  throw Error('Frozen invalid Sophos mutation SHA changed');
const mutations=JSON.parse(mutationBytes.toString('utf8')) as SourceRow[];
let invalidLexical=0,invalidLocated=0,invalidVendorPass=0,invalidVeto=0,
    invalidAutoPromoted=0;
for(const row of mutations){
  const lexical=conservativeKvFields(row.raw);
  const located=conservativeKvLocatedFields(row.raw);
  if(!!lexical!==!!located)
    throw Error('New observer silently altered grammatical acceptance');
  if(lexical)invalidLexical++;
  if(located)invalidLocated++;
  const baseline=parseSecurityInput(row.raw);
  const event=baseline.ok&&baseline.events.length===1?baseline.events[0]:undefined;
  const originalVendor=event?.fields.sophos as Record<string,unknown>|undefined;
  const existingProfile=!!originalVendor?.fields&&typeof originalVendor.fields==='object';
  if(existingProfile)invalidVendorPass++;
  const veto=classifyVendorSourceReview({
    lexicalCandidate:!!located,originalSourceShaMatches:true,exactRawRetained:true,
    independentSourceVerdict:'UNSCORED',
    existingVendorProfile:existingProfile?'PASS':'FAIL',
  });
  if(veto.disposition==='EXISTING_VENDOR_PROFILE_VETO')invalidVeto++;
  if(veto.canAutoPromote||veto.originalSourceVerified)invalidAutoPromoted++;
}
if(events!==185||fields!==4160||mutations.length!==900||
  reference.counts.byteSpanQualifiedFields!==4160||
  invalidLexical!==600||invalidLocated!==600||invalidVeto!==600||
  invalidAutoPromoted!==0||invalidVendorPass!==0||
  sourceIdentityErrors>0||sourceUnscorable>0)
  throw Error('Source reference accounting or negative safety gate drift');
console.log('SOURCE_KV_UTF8_BYTE_SPAN_INDEPENDENT_AUDIT '+JSON.stringify({
  originalEvents:events,originalFields:fields,exactEvents,exactFields,
  falsePositive,falseNegative,spanMismatch,valueMismatch,
  sourceUnscorable,candidateRejected,sourceIdentityErrors,bytesRetained,
  independentSourceOracleSha256:sha(fs.readFileSync(privateOracle)),
  frozenOriginalSourceSha256:fixed.originals,byFamily,
  invalidMutations:mutations.length,invalidLexical,invalidLocated,
  invalidExistingVendorAccepted:invalidVendorPass,invalidVeto,
  invalidAutoPromoted,publication:'COUNTERS_AND_SHA_ONLY',
  vendorEscapeSemantics:'NOT_CERTIFIED',nativeTarget:'NOT_VERIFIED',
  productParserModified:false,rawOrFieldValuesPrinted:false,
}));
if(falsePositive||falseNegative||spanMismatch||valueMismatch||
   exactEvents!==events||exactFields!==fields||candidateRejected)process.exitCode=1;
