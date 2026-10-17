/** Source-only conservative escape PoC, against frozen private independent oracles. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {conservativeKvFields} from '../../src/poc/conservativeKvGrammar';
import {sourceKvReference,scoreKvFields} from '../../src/poc/syslogKvFieldFidelity';

type Reference={sourceSha256:string;family:string;fields:unknown};
type Source={sha256:string;file:string;fields:unknown};
type Sonic={sha256:string;fields:unknown};
type Count={events:number;fields:number;baselineExact:number;candidateExact:number;
  baselineFP:number;baselineFN:number;candidateFP:number;candidateFN:number;
  baselineExactEvents:number;candidateExactEvents:number;candidateRejected:number};
const blank=():Count=>({events:0,fields:0,baselineExact:0,candidateExact:0,
  baselineFP:0,baselineFN:0,candidateFP:0,candidateFN:0,
  baselineExactEvents:0,candidateExactEvents:0,candidateRejected:0});
const root=path.join(os.homedir(),'.local/state');
const previous=path.join(root,'parserstudio-lossless-blind-20261017');
const fresh=path.join(root,'parserstudio-fresh-kv-20261017');
const sonic=path.join(root,'parserstudio-fresh-sonicwall-20261017');
const sha=(v:string|Buffer)=>createHash('sha256').update(v).digest('hex');
const read=<T>(filename:string):T=>JSON.parse(fs.readFileSync(filename,'utf8')) as T;
const count:Record<'oldSonicwall'|'oldFortinet'|'newFortinet'|'newSonicwall',Count>={
  oldSonicwall:blank(),oldFortinet:blank(),newFortinet:blank(),newSonicwall:blank(),
};
const sourceHashes=new Set<string>();
let candidateAcceptedUnscorable=0,unscorableEvents=0,previousDifferentFields=0,
  candidateMatchesUpstreamForDifference=0,baselineMatchesUpstreamForDifference=0;
const upstreamExpectedPath=path.join(root,'parserstudio-fortinet-escape-semantics-20261017',
  'elastic-fortinet-7-2-upstream-expected.json');
const upstreamBlob=fs.readFileSync(upstreamExpectedPath);
if(sha(upstreamBlob)!=='bb6b797f98987db075899ad4eeea5adc3e7a884b959820aa7082ebcaf3eaef36')
  throw Error('Pinned independent upstream expected-output SHA drift');
const upstream=read<Record<string,Record<string,unknown>[]>>(upstreamExpectedPath);
const upstreamRecords=Object.values(upstream)[0]!;
if(!Array.isArray(upstreamRecords)||upstreamRecords.length!==7)
  throw Error('Pinned vendor-upstream expected-output event count drift');
const upstreamBySource=new Map<string,Record<string,unknown>>();
for(const event of upstreamRecords){
  const orig=(event.event as Record<string,unknown>|undefined)?.original;
  if(typeof orig!=='string')throw Error('Expected upstream event source missing');
  upstreamBySource.set(sha(orig),event);
}
if(upstreamBySource.size!==7)throw Error('Upstream golden source identity collision');

function compare(group:keyof typeof count,raw:string,oracle:{sha256:string;fields:unknown},
  fixed:'fortinet.fields'|'generic.kv'):void{
  const hash=sha(raw);
  if(hash!==oracle.sha256||sourceHashes.has(hash))
    throw Error('Source oracle hash conflict or original source overlap');
  sourceHashes.add(hash);
  const expected=sourceKvReference(oracle.fields);
  const baseline=parseSecurityInput(raw);
  const event=baseline.ok&&baseline.events.length===1?baseline.events[0]:undefined;
  const vendor=event?.fields.fortinet as Record<string,unknown>|undefined;
  const generic=event?.fields.generic as Record<string,unknown>|undefined;
  const actual=fixed==='fortinet.fields'?vendor?.fields:generic?.kv;
  const measuredBaseline=scoreKvFields(expected,actual);
  const candidate=conservativeKvFields(raw);
  const measuredCandidate=scoreKvFields(expected,candidate?.fields);
  const c=count[group];c.events++;c.fields+=expected.size;
  c.baselineExact+=measuredBaseline.exact;
  c.candidateExact+=measuredCandidate.exact;
  c.baselineFP+=measuredBaseline.wrongValue+measuredBaseline.unexpected;
  c.baselineFN+=measuredBaseline.wrongValue+measuredBaseline.missing;
  c.candidateFP+=measuredCandidate.wrongValue+measuredCandidate.unexpected;
  c.candidateFN+=measuredCandidate.wrongValue+measuredCandidate.missing;
  if(measuredBaseline.exactEvent)c.baselineExactEvents++;
  if(measuredCandidate.exactEvent)c.candidateExactEvents++;
  if(!candidate)c.candidateRejected++;
  if(group==='oldFortinet'){
    const golden=upstreamBySource.get(hash);
    if(!golden)throw Error('Fortinet upstream expected source not found');
    const vendorGold=(golden.fortinet as Record<string,unknown>|undefined)?.firewall;
    if(!vendorGold||typeof vendorGold!=='object'||Array.isArray(vendorGold))
      throw Error('Fortinet upstream vendor value contract missing');
    const vendorMap=vendorGold as Record<string,unknown>;
    const baselineMap=actual&&typeof actual==='object'&&!Array.isArray(actual)
      ?actual as Record<string,unknown>:{};
    const candidateMap=candidate?.fields??{};
    for(const [name,value] of expected){
      if(baselineMap[name]===value)continue;
      previousDifferentFields++;
      if(Object.hasOwn(vendorMap,name)&&vendorMap[name]===candidateMap[name]&&
         candidateMap[name]===value)candidateMatchesUpstreamForDifference++;
      if(Object.hasOwn(vendorMap,name)&&vendorMap[name]===baselineMap[name])
        baselineMatchesUpstreamForDifference++;
    }
  }
}
const originalBytes=fs.readFileSync(path.join(previous,'records.json'));
if(sha(originalBytes)!=='153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32')
  throw Error('Old frozen original records changed');
const old=JSON.parse(originalBytes.toString('utf8')) as {id:string;source:string;raw:string}[];
const originalOracle=read<Record<string,Reference>>(
  path.join(previous,'oracle-blind-syslog-kv-fields.json'));
if(old.length!==222||Object.keys(originalOracle).length!==185)
  throw Error('Old independent source denominator drifted');
const allOldHashes=new Set(old.map(x=>sha(x.raw)));
if(allOldHashes.size!==222)throw Error('Old source original duplicates');
for(const row of old){
  const reference=originalOracle[row.id];
  if(!reference)continue;
  const sourceVendor=row.source.split('/')[1];
  if(reference.family!==sourceVendor)throw Error('Old reference family mismatch');
  const fortinet=sourceVendor==='fortinet_fortigate';
  if(!fortinet&&sourceVendor!=='sonicwall_firewall')
    throw Error('Unexpected original source family');
  compare(fortinet?'oldFortinet':'oldSonicwall',row.raw,
    {sha256:reference.sourceSha256,fields:reference.fields},
    fortinet?'fortinet.fields':'generic.kv');
}
const newOracle=read<Record<string,Source>>(path.join(fresh,'oracle-fresh-bare-kv-fields.json'));
if(Object.keys(newOracle).length!==1002)throw Error('Fresh Fortinet denominator changed');
const freshFiles=[
  ['fg.log','e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2'],
  ['fg_long.log','53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440'],
] as const;
const freshSeen=new Set<string>();
let freshPhysical=0,duplicates=0;
for(const [name,digest] of freshFiles){
  const buf=fs.readFileSync(path.join(fresh,name));
  if(sha(buf)!==digest)throw Error('Fresh Fortinet source changed');
  for(const raw of buf.toString('utf8').split(/\r\n|\n|\r/).filter(x=>x.trim())){
    freshPhysical++;
    const hash=sha(raw);
    if(freshSeen.has(hash)){duplicates++;continue;}
    freshSeen.add(hash);
    if(allOldHashes.has(hash))throw Error('New Fortinet overlaps old source');
    const item=newOracle[hash];
    if(!item||item.file!==name)throw Error('New Fortinet source not in independent oracle');
    compare('newFortinet',raw,item,'generic.kv');
  }
}
if(freshPhysical!==1008||duplicates!==6)
  throw Error('Fresh Fortinet record accounting drift');
const sonicBytes=fs.readFileSync(path.join(sonic,'sonicwall.log.orig'));
if(sha(sonicBytes)!=='949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9')
  throw Error('Fresh original SonicWall source changed');
const sonicOracle=read<{accepted:Record<string,Sonic>;unscorableSourceSha256:string[]}>(
  path.join(sonic,'oracle-fresh-sonicwall-syslog-kv.json'));
if(Object.keys(sonicOracle.accepted).length!==59||sonicOracle.unscorableSourceSha256.length!==2)
  throw Error('Fresh SonicWall oracle denominator changed');
const unscorable=new Set(sonicOracle.unscorableSourceSha256);
for(const raw of sonicBytes.toString('utf8').split(/\r\n|\n|\r/).filter(x=>x.trim())){
  const hash=sha(raw);
  if(allOldHashes.has(hash)||freshSeen.has(hash))
    throw Error('Fresh SonicWall overlaps previous source');
  const reference=sonicOracle.accepted[hash];
  if(!reference){
    if(!unscorable.has(hash))throw Error('Unqualified SonicWall source missing rejection');
    unscorableEvents++;
    if(conservativeKvFields(raw)!==null)candidateAcceptedUnscorable++;
    continue;
  }
  compare('newSonicwall',raw,reference,'generic.kv');
}
const c=Object.values(count);
const sum=(key:keyof Count)=>c.reduce((acc,x)=>acc+x[key],0);
if(count.oldFortinet.events!==7||count.oldSonicwall.events!==178||
   count.newFortinet.events!==1002||count.newSonicwall.events!==59||
   sum('events')!==1246||sum('fields')!==16767||
   sum('baselineExact')!==16766||sum('baselineFP')!==1||sum('baselineFN')!==1||
   previousDifferentFields!==1||candidateMatchesUpstreamForDifference!==1||
   baselineMatchesUpstreamForDifference!==0||unscorableEvents!==2)
  throw Error('Frozen baseline or independent upstream escape evidence drifted');
console.log('CONSERVATIVE_ESCAPE_GRAMMAR_SOURCE_COMPARISON '+JSON.stringify({
  originalQualifiedEvents:sum('events'),independentOriginalFields:sum('fields'),
  oldParserExactSourceFields:sum('baselineExact'),
  candidateExactSourceFields:sum('candidateExact'),
  baselineFP:sum('baselineFP'),baselineFN:sum('baselineFN'),
  candidateFP:sum('candidateFP'),candidateFN:sum('candidateFN'),
  baselineExactEvents:sum('baselineExactEvents'),
  candidateExactEvents:sum('candidateExactEvents'),
  candidateRejectedQualifiedEvents:sum('candidateRejected'),
  separatelyUnscorableOriginalEvents:unscorableEvents,
  candidateAcceptedUnscorable,
  upstreamSourceIdentityAlignedExpectedEvents:upstreamBySource.size,
  priorDifferingEscapedFields:previousDifferentFields,
  candidateAgreesWithUpstreamGoldenOnPriorDifference:candidateMatchesUpstreamForDifference,
  oldDecoderAgreesWithUpstreamGoldenOnPriorDifference:baselineMatchesUpstreamForDifference,
  byCohort:count,
  candidateState:'UNPROMOTED_ISOLATED_SOURCE_POC',
  manufacturerEscapeSemantics:'NOT_CERTIFIED',
  productParserModified:false,
  nativeTargetApproved:false,
  rawOrSourceValuesPrinted:false,
}));
if(sum('candidateFN')>sum('baselineFN')||
   sum('candidateFP')>sum('baselineFP')||
   candidateAcceptedUnscorable>0)process.exitCode=1;
