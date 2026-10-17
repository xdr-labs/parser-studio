/** New provenance fail-closed audit; reuses frozen source corpora only as controls.
 * Does not rerun previous field accuracy studies or emit raw/private field values.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {judgeVendorEscapeProvenance,type Producer,type WireProfile}
  from '../../src/poc/vendorEscapeProvenanceGate';
import {conservativeKvLocatedFields} from '../../src/poc/conservativeKvUtf8Span';

type SourceRow={id:string;source:string;raw:string};
type Reference={sourceSha256:string;status?:string;family?:string};
const root=path.join(os.homedir(),'.local/state');
const sha=(v:string|Buffer)=>createHash('sha256').update(v).digest('hex');
function pinned(relative:string,expected:string):Buffer{
  const b=fs.readFileSync(path.join(root,relative));
  if(sha(b)!==expected)throw Error('Pinned original / negative source SHA drift');
  return b;
}
const old=pinned('parserstudio-lossless-blind-20261017/records.json',
  '153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32');
const oldRefs=JSON.parse(fs.readFileSync(path.join(root,
  'parserstudio-lossless-blind-20261017/oracle-blind-syslog-kv-fields.json'),'utf8')) as Record<string,Reference>;
const additional=pinned(
  'parserstudio-source-kv-byte-span-20261017/additional-source-kv-utf8-byte-spans.json',
  'd45ae3af2fb68f6efa8527d281df30e4dce648ffc7b2c271e60a943dfc034f78');
const additionalRefs=(JSON.parse(additional.toString('utf8')) as
  {records:Record<string,Reference>}).records;
if(Object.keys(oldRefs).length!==185||Object.keys(additionalRefs).length!==1214)
  throw Error('Previous independently qualified source denominator drift');
const sourceSeen=new Set<string>();
const categories:Record<string,{events:number;fixtureOnly:number;wireShapeConflicts:number;
  unscorable:number;automaticallyPromoted:number}>={};
function inspect(original:string,category:string,producer:Producer,profile:WireProfile,
  independentlyScorable:boolean):void{
  const hash=sha(original);
  if(sourceSeen.has(hash))throw Error('Qualified source reused by multiple cohorts');
  sourceSeen.add(hash);
  const c=categories[category]??={events:0,fixtureOnly:0,
    wireShapeConflicts:0,unscorable:0,automaticallyPromoted:0};
  c.events++;
  const result=judgeVendorEscapeProvenance({
    raw:Buffer.from(original,'utf8'),pinnedSourceSha256:hash,
    producer,profile,origin:'PINNED_REPO_FIXTURE',version:null,
    configuration:null,semanticExpected:null,
  });
  if(result.canAutoPromote||result.manufacturerSemantics!=='NOT_CERTIFIED')
    throw Error('Prior source-fidelity success incorrectly became manufacturer success');
  if(result.disposition==='SOURCE_FIXTURE_NOT_DEVICE_PROOF')c.fixtureOnly++;
  else if(result.disposition==='WIRE_SHAPE_CONFLICT')c.wireShapeConflicts++;
  else c.unscorable++;
  if(!independentlyScorable&&result.disposition==='DEVICE_EVIDENCE_EXTERNAL_REVIEW_ONLY')
    throw Error('Unscorable original reached semantic review');
}
const oldRows=JSON.parse(old.toString('utf8')) as SourceRow[];
if(oldRows.length!==222)throw Error('Old source count changed');
for(const row of oldRows){
  const ref=oldRefs[row.id];if(!ref)continue;
  if(ref.sourceSha256!==sha(row.raw))throw Error('Old original identity changed');
  const fortinet=row.source.includes('fortinet_fortigate');
  inspect(row.raw,fortinet?'oldFortinet':'oldSonicWall',
    fortinet?'FORTIGATE':'SONICWALL',
    fortinet?'FORTIGATE_FGT':'SONICOS_ENHANCED',true);
}
let freshPhysical=0,freshDuplicates=0;
const newFortinet=new Set<string>();
for(const [file,expected] of [
  ['fg.log','e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2'],
  ['fg_long.log','53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440'],
] as const){
  const b=pinned('parserstudio-fresh-kv-20261017/'+file,expected);
  for(const original of b.toString('utf8').split(/\r\n|\n|\r/).filter(s=>s.trim())){
    freshPhysical++;
    const hash=sha(original);
    if(newFortinet.has(hash)){freshDuplicates++;continue;}
    newFortinet.add(hash);
    if(additionalRefs[hash]?.status!=='SOURCE_QUALIFIED')
      throw Error('New Fortinet original lost independent source qualification');
    inspect(original,'freshFortinet','FORTIGATE','FORTIGATE_FGT',true);
  }
}
if(freshPhysical!==1008||freshDuplicates!==6)
  throw Error('Fresh Fortinet source cardinality changed');
const sonic=pinned('parserstudio-fresh-sonicwall-20261017/sonicwall.log.orig',
  '949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9');
for(const original of sonic.toString('utf8').split(/\r\n|\n|\r/).filter(s=>s.trim())){
  const ref=additionalRefs[sha(original)];
  if(!ref)throw Error('Original SonicWall expected SHA missing');
  inspect(original,'freshSonicWall','SONICWALL','SONICOS_ENHANCED',
    ref.status==='SOURCE_QUALIFIED');
}
const vendor=pinned('parserstudio-fresh-vendor-holdout-20261016/records.json',
  '3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2');
const vendorRows=JSON.parse(vendor.toString('utf8')) as SourceRow[];
if(vendorRows.length!==571)throw Error('Vendor original denominator drift');
let sophosRepeatedPhysical=0,sophosPhysical=0;
for(const row of vendorRows.filter(x=>x.source.startsWith('sophos/xg/'))){
  sophosPhysical++;
  if(sourceSeen.has(sha(row.raw))){sophosRepeatedPhysical++;continue;}
  const ref=additionalRefs[sha(row.raw)];
  inspect(row.raw,'sophos','SOPHOS_FIREWALL','SOPHOS_STANDARD',
    ref?.status==='SOURCE_QUALIFIED');
}
if(sophosPhysical!==271||sophosRepeatedPhysical!==1||
   categories.oldFortinet?.events!==7||categories.oldSonicWall?.events!==178||
   categories.freshFortinet?.events!==1002||
   categories.freshSonicWall?.events!==61||categories.sophos?.events!==270)
  throw Error('Frozen original cohort count shifted');

// New gate negative replay (NOT renewed source-value accuracy qualification).
const nonVendor=pinned('parserstudio-ext-holdout-20261016/records.json',
  'dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e');
const externalRows=JSON.parse(nonVendor.toString('utf8')) as SourceRow[];
if(externalRows.length!==790)throw Error('External source denominator drift');
let frozenOriginals=0,originalAutoPromoted=0;
for(const row of [...vendorRows,...externalRows]){
  frozenOriginals++;
  const result=judgeVendorEscapeProvenance({
    raw:Buffer.from(row.raw),pinnedSourceSha256:sha(row.raw),
    producer:'FORTIGATE',profile:'FORTIGATE_FGT',
    origin:'PINNED_REPO_FIXTURE',version:null,
    configuration:null,semanticExpected:null,
  });
  if(result.canAutoPromote)originalAutoPromoted++;
}
let mutated=0,mutationAutoPromoted=0,sophosLexical=0;
for(const spec of [
  ['parserstudio-fresh-vendor-holdout-20261016/known_invalid.json',
   'da46f85025b99a9f735aa6309d95d49d396c9b23586d0392aaa6d8d40f00fae2',1],
  ['parserstudio-ext-holdout-20261016/adversarial.json',
   '9d2350c6f467532f2b226600320b5ffb61f9fd21bb9bd180737e7b57d26bd45c',1532],
  ['parserstudio-fresh-vendor-holdout-20261016/junos_bare_mutations.json',
   '389b8b2dc3766ca23f338bd37a36cec83e5300176ddf7caf5ad30a4dec402bb7',45],
  ['parserstudio-fresh-vendor-holdout-20261016/junos_bracket_mutations.json',
   '5c95c30925e3f67b2999510edb7a001e3790f715a6aa0fe6bcda50853d9ba166',414],
  ['parserstudio-fresh-vendor-holdout-20261016/sophos_kv_mutations.json',
   '1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82',900],
] as const){
  const rows=JSON.parse(pinned(spec[0],spec[1]).toString('utf8')) as SourceRow[];
  if(rows.length!==spec[2])throw Error('Frozen mutation count changed');
  for(const row of rows){
    mutated++;
    if(spec[2]===900&&conservativeKvLocatedFields(row.raw))sophosLexical++;
    const r=judgeVendorEscapeProvenance({
      raw:Buffer.from(row.raw),pinnedSourceSha256:sha(row.raw),
      producer:'SOPHOS_FIREWALL',profile:'SOPHOS_STANDARD',
      origin:'PINNED_REPO_FIXTURE',version:null,
      configuration:null,semanticExpected:null,
    });
    if(r.canAutoPromote)mutationAutoPromoted++;
  }
}
if(frozenOriginals!==1361||mutated!==2892||sophosLexical!==600||
   originalAutoPromoted||mutationAutoPromoted)
  throw Error('Source provenance gate falsely certified frozen original/mutation');
console.log('VENDOR_ESCAPE_PROVENANCE_ORIGINAL_AND_NEGATIVE_AUDIT '+JSON.stringify({
  distinctOriginalsForManufacturerClaimAudit:sourceSeen.size,
  sophosPhysicalOriginals:sophosPhysical,sophosRepeatedPhysical,
  originalByCohort:categories,
  otherOriginalCrossProfileUntrustedClaims:frozenOriginals,
  malformedCrossProfileUntrustedClaims:mutated,
  sophosInvalidLexicalAccepted:sophosLexical,
  falseCompleteVendorPromotions:originalAutoPromoted+mutationAutoPromoted,
  authoritativeWireConfigWithExactDeviceVersionAvailable:0,
  independentManufacturerSemanticGoldenAvailable:0,
  manufacturerSemantics:'NOT_CERTIFIED',nativeTarget:'NOT_VERIFIED',
  originalValuesPrinted:false,productParserModified:false,
}));
