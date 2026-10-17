/** Isolated private-source cross-corpus trust gate; prints only aggregate evidence. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {sourceKvReference} from '../../src/poc/syslogKvFieldFidelity';
import {evaluateSourceKvTrust,type SourceKvQualification} from '../../src/poc/sourceKvTrustBoundary';

type SourceOracle={sourceSha256:string;family:string;fields:unknown};
type FreshOracle={sha256:string;file:string;fields:unknown};
type SonicOracle={sha256:string;fields:unknown;variant:string};
type Counts={records:number;qualified:number;fields:number;extracted:number;exact:number;
  wrong:number;missing:number;unexpected:number;structuralAccepts:number;
  sourceFieldExactEvents:number;sourceFieldMismatchEvents:number;unscorable:number;
  statuses:Record<SourceKvQualification,number>};
const newCounts=():Counts=>({records:0,qualified:0,fields:0,extracted:0,exact:0,
  wrong:0,missing:0,unexpected:0,structuralAccepts:0,
  sourceFieldExactEvents:0,sourceFieldMismatchEvents:0,unscorable:0,
  statuses:{
    SOURCE_FIELD_EXACT:0,SOURCE_FIELD_MISMATCH:0,SOURCE_UNSCORABLE:0,
    ORACLE_SOURCE_DRIFT:0,PARSER_NOT_SINGLE_EVENT:0,RAW_NOT_PRESERVED:0,
  }});
const roots={
  elastic:path.join(os.homedir(),'.local/state/parserstudio-lossless-blind-20261017'),
  fortinet:path.join(os.homedir(),'.local/state/parserstudio-fresh-kv-20261017'),
  sonicwall:path.join(os.homedir(),'.local/state/parserstudio-fresh-sonicwall-20261017'),
};
const hash=(item:string|Buffer)=>createHash('sha256').update(item).digest('hex');
const json=<T>(file:string):T=>JSON.parse(fs.readFileSync(file,'utf8')) as T;
const index=new Set<string>();
const allPriorOriginalHashes=new Set<string>();
const count:Record<'elasticSonicwall'|'elasticFortinet'|'freshFortinet'|'freshSonicwall',Counts>={
  elasticSonicwall:newCounts(),elasticFortinet:newCounts(),
  freshFortinet:newCounts(),freshSonicwall:newCounts(),
};
function record(group:keyof typeof count,raw:string,oracle:null|{sha256:string;fields:unknown},
  fieldContract:'fortinet.fields'|'generic.kv'):void{
  const id=hash(raw);
  if(group.startsWith('fresh')&&allPriorOriginalHashes.has(id))
    throw Error('Fresh source overlaps any prior original, including unscored formats');
  if(index.has(id))throw Error('Cross-corpus original source SHA overlap');
  index.add(id);
  if(oracle&&id!==oracle.sha256)throw Error('Frozen reference source SHA drift');
  const result=parseSecurityInput(raw);
  const reference=oracle?sourceKvReference(oracle.fields):null;
  const verdict=evaluateSourceKvTrust({raw,result,expected:reference,
    sourceSha256:oracle?.sha256??null,fixedContract:fieldContract});
  const c=count[group];
  c.records++;
  if(verdict.structurallyAccepted)c.structuralAccepts++;
  c.statuses[verdict.qualification]++;
  if(!reference){c.unscorable++;return;}
  c.qualified++;
  c.fields+=reference.size;
  c.extracted+=verdict.score?.extracted??0;
  c.exact+=verdict.score?.exact??0;
  c.wrong+=verdict.score?.wrongValue??0;
  c.missing+=verdict.score?.missing??reference.size;
  c.unexpected+=verdict.score?.unexpected??0;
  if(verdict.qualification==='SOURCE_FIELD_EXACT')c.sourceFieldExactEvents++;
  if(verdict.qualification==='SOURCE_FIELD_MISMATCH')c.sourceFieldMismatchEvents++;
}
const oldBytes=fs.readFileSync(path.join(roots.elastic,'records.json'));
if(hash(oldBytes)!=='153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32')
  throw Error('Old source records SHA drift');
const old=json<{id:string;source:string;raw:string}[]>(path.join(roots.elastic,'records.json'));
for(const original of old){
  const id=hash(original.raw);
  if(allPriorOriginalHashes.has(id))throw Error('Frozen source contains duplicate physical originals');
  allPriorOriginalHashes.add(id);
}
const oldOracle=json<Record<string,SourceOracle>>(
  path.join(roots.elastic,'oracle-blind-syslog-kv-fields.json'));
if(old.length!==222||Object.keys(oldOracle).length!==185)
  throw Error('Old source qualification denominator drifted');
for(const row of old){
  if(!Object.hasOwn(oldOracle,row.id))continue; // 22 JSON and 15 ASA deliberately outside this KV evaluation
  const proof=oldOracle[row.id]!;
  const family=row.source.split('/')[1];
  if(family!==proof.family)throw Error('Old source family drift');
  const fortinet=family==='fortinet_fortigate';
  if(!fortinet&&family!=='sonicwall_firewall')throw Error('Unrecognized source contract');
  record(fortinet?'elasticFortinet':'elasticSonicwall',row.raw,
    {sha256:proof.sourceSha256,fields:proof.fields},
    fortinet?'fortinet.fields':'generic.kv');
}
const freshOracle=json<Record<string,FreshOracle>>(
  path.join(roots.fortinet,'oracle-fresh-bare-kv-fields.json'));
if(Object.keys(freshOracle).length!==1002)
  throw Error('New Fortinet source qualification drift');
const freshPins=[
  ['fg.log','e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2'],
  ['fg_long.log','53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440'],
] as const;
let freshPhysical=0,freshDuplicates=0;
const freshHashes=new Set<string>();
for(const [name,expectedSha] of freshPins){
  const blob=fs.readFileSync(path.join(roots.fortinet,name));
  if(hash(blob)!==expectedSha)throw Error('New Fortinet pinned fixture drift');
  for(const raw of blob.toString('utf8').replace(/^\uFEFF/,'').split(/\r\n|\n|\r/).filter(Boolean)){
    freshPhysical++;
    const id=hash(raw);
    if(freshHashes.has(id)){freshDuplicates++;continue;}
    freshHashes.add(id);
    const item=freshOracle[id];
    if(!item||item.file!==name||item.sha256!==id)
      throw Error('Independent fresh Fortinet event not frozen before scoring');
    record('freshFortinet',raw,item,'generic.kv');
  }
}
if(freshPhysical!==1008||freshDuplicates!==6)
  throw Error('Fresh Fortinet duplicate accounting drifted');
const sonicPath=path.join(roots.sonicwall,'sonicwall.log.orig');
const sonicBytes=fs.readFileSync(sonicPath);
if(hash(sonicBytes)!=='949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9')
  throw Error('Pinned original SonicWall SHA drift');
const sonicOracle=json<{accepted:Record<string,SonicOracle>;unscorableSourceSha256:string[];
  sourceFileHash:string;revision:string}>(path.join(roots.sonicwall,'oracle-fresh-sonicwall-syslog-kv.json'));
if(sonicOracle.revision!=='bc8c137fe913ba43a4345850206565b028e8fef8'||
  sonicOracle.sourceFileHash!==hash(sonicBytes)||
  Object.keys(sonicOracle.accepted).length!==59||
  sonicOracle.unscorableSourceSha256.length!==2)
  throw Error('Fresh SonicWall independent Oracle drift');
const excluded=new Set(sonicOracle.unscorableSourceSha256);
for(const raw of sonicBytes.toString('utf8').replace(/^\uFEFF/,'').split(/\r\n|\n|\r/).filter(Boolean)){
  const id=hash(raw);
  const proof=sonicOracle.accepted[id];
  if(proof&&proof.variant!=='yearless')throw Error('Unexpected SonicWall original source grammar');
  if(!proof&&!excluded.has(id))throw Error('Unqualified new source was not rejected explicitly');
  record('freshSonicwall',raw,proof?{sha256:proof.sha256,fields:proof.fields}:null,'generic.kv');
}
const eSw=count.elasticSonicwall,eFt=count.elasticFortinet,
  fFt=count.freshFortinet,fSw=count.freshSonicwall;
if(eSw.qualified!==178||eSw.fields!==3869||eSw.sourceFieldExactEvents!==178||
   eFt.qualified!==7||eFt.fields!==291||eFt.sourceFieldExactEvents!==6||
   eFt.sourceFieldMismatchEvents!==1||
   fFt.qualified!==1002||fFt.fields!==11848||fFt.sourceFieldExactEvents!==1002||
   fSw.records!==61||fSw.qualified!==59||fSw.fields!==759||
   fSw.sourceFieldExactEvents!==59||fSw.unscorable!==2||
   fSw.structuralAccepts!==61)
  throw Error('Frozen source fidelity outcomes drifted; requires review');
const groups=Object.values(count);
const sum=(key:Exclude<keyof Counts,'statuses'>)=>groups.reduce((a,b)=>a+b[key],0);
if(sum('qualified')!==1246||sum('fields')!==16767||sum('exact')!==16766||
   sum('wrong')!==1||sum('missing')!==0||sum('unexpected')!==0||
   sum('sourceFieldExactEvents')!==1245||sum('sourceFieldMismatchEvents')!==1||
   sum('unscorable')!==2||sum('records')!==1248)
  throw Error('Cross-corpus trust boundary total drifted');
console.log('SOURCE_KV_INDEPENDENT_TRUST_BOUNDARY '+JSON.stringify({
  qualifiedSourceRecords:sum('qualified'),
  independentlyQualifiedSourceFields:sum('fields'),
  exactlyMatchedSourceFields:sum('exact'),
  sourceFieldExactEvents:sum('sourceFieldExactEvents'),
  sourceFieldMismatchEvents:sum('sourceFieldMismatchEvents'),
  explicitlyUnscorableRecords:sum('unscorable'),
  sourceRawRecordsEvaluated:sum('records'),
  falsePositive:sum('wrong')+sum('unexpected'),
  falseNegative:sum('wrong')+sum('missing'),
  structurallyAcceptedButUnscorable:fSw.unscorable,
  sourceValueMismatchRetained:eFt.sourceFieldMismatchEvents,
  countsByEvidenceCohort:count,
  singleGlobalGeneralizationRate:'NOT_SUPPORTED',
  semanticApproved:false,nativeApproved:false,
  deploymentApproved:false,sourceFieldsOrRawLogged:false,
}));
