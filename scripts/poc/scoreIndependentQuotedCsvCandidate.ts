/** New stage compared with the PRE-FROZEN upstream publisher CSV oracle, not own output. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {scanDelimitedRow} from '../../src/poc/losslessLexer';
import {replayCandidate} from '../../src/poc/grammarFunnel';
import {inspectIndependentQuotedCsv} from '../../src/poc/independentQuotedCsvSource';
const root=path.join(os.homedir(),'.local/state/parserstudio-independent-quoted-csv-20261017');
const sha=(x:Buffer)=>crypto.createHash('sha256').update(x).digest('hex');
const source=fs.readFileSync(path.join(root,'sources.pinned.json'));
const oracle=fs.readFileSync(path.join(root,'author-expected-original-csv.v1.json'));
const meta=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v1.pinned.json'),'utf8'));
if(meta.stage!=='FROZEN_BEFORE_ANY_PRODUCT_BASELINE_OR_POC_SCORE'||
   meta.oracle_sha256!=='21df0514536935d5361e73b5cfbc4a263f8eb796caf27e4214e380d38a29427b'||
   sha(oracle)!==meta.oracle_sha256||sha(source)!==meta.source_pin_sha256)
  throw Error('Independent publisher CSV oracle is missing or not immutable');
type Cell={ordinal:number;decoded_value:string|null;start_byte:number;end_byte:number;raw_span:string};
type Named=Cell&{name:string;header_name_span:{start_byte:number;end_byte:number;raw_span:string}};
type Row={id:string;status:string;raw:string;raw_sha256:string;raw_bytes:number;
 expected:Cell[]|Named[];header_raw?:string;header_sha256?:string;row_raw?:string;row_sha256?:string};
type Metric={events:number;expected:number;TP:number;FP:number;FN:number;
 exactEvents:number;reviewOnly:number;abstained:number;rawDrift:number;
 autoPromotion:number;branchOver8:number;latencyMs:number[]};
const empty=():Metric=>({events:0,expected:0,TP:0,FP:0,FN:0,exactEvents:0,
 reviewOnly:0,abstained:0,rawDrift:0,autoPromotion:0,branchOver8:0,latencyMs:[]});
const before=empty(),after=empty(),byCategory:Record<string,{before:Metric;after:Metric}>={};
const nameBefore=empty(),nameAfter=empty();
let profileInvalid=0,profileVetoEscapes=0,unqualifiedCsvPromotions=0;
const rows=JSON.parse(oracle.toString('utf8')) as Row[];
if(rows.length!==meta.originals||
   rows.filter(r=>r.status==='POSITIONAL_SCORABLE').length!==meta.positional_events)
  throw Error('Frozen CSV denominator or eligibility changed');
function category(row:Row):string{
 if(/[\r\n]/.test(row.raw))return 'embedded_newline';
 if(row.raw.includes('""'))return 'doubled_quotes';
 if(row.expected.some(x=>x.decoded_value===null))return 'empty_unquoted';
 if(row.expected.length<3)return 'one_or_two_columns';
 return row.raw.includes('"')?'quoted':'plain_three_plus';
}
function add(metric:Metric,expected:Cell[],found:Array<{
 ordinal:number;value:string|null;startByte:number;endByte:number
}>,review:boolean,time:number){
 metric.events++;metric.expected+=expected.length;
 metric.reviewOnly+=Number(review);metric.abstained+=Number(!review);
 metric.latencyMs.push(time);
 let tp=0,fp=0;
 for(const cell of expected){
   const named=found[cell.ordinal];
   if(named&&named.ordinal===cell.ordinal&&
      named.value===cell.decoded_value&&named.startByte===cell.start_byte&&
      named.endByte===cell.end_byte)tp++;
   else if(named)fp++;
 }
 fp+=Math.max(0,found.length-expected.length);
 metric.TP+=tp;metric.FP+=fp;metric.FN+=expected.length-tp;
 metric.exactEvents+=Number(tp===expected.length&&fp===0);
}
for(const row of rows){
 const original=Buffer.from(row.raw,'utf8');
 if(sha(original)!==row.raw_sha256||original.length!==row.raw_bytes)
   throw Error('Frozen original source CSV wire bytes changed');
 if(row.status==='UPSTREAM_INVALID_ONLY_WITH_PROFILE'){
   profileInvalid++;
   const veto=inspectIndependentQuotedCsv(row.raw,{recordFraming:'CONFIRMED_SINGLE_CSV_RECORD'},
      {sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'UNSCORED'});
   profileVetoEscapes+=Number(veto.disposition!=='ABSTAIN_UNSAFE'||
    veto.positionalClaims.length>0||veto.namedClaims.length>0||veto.autoPromoted);
   continue;
 }
 if(row.status==='DUPLICATE_ORIGINAL_EXCLUDED'||row.status==='UNSCORABLE_UPSTREAM_DIALECT')continue;
 if(row.status==='SOURCE_NAMED_HEADER_SESSION'){
   if(!row.header_raw||!row.row_raw||sha(Buffer.from(row.header_raw,'utf8'))!==row.header_sha256||
      sha(Buffer.from(row.row_raw,'utf8'))!==row.row_sha256)
      throw Error('Upstream separate header/data raw message SHA drift');
   const reference=row.expected as Named[];
   const named=inspectIndependentQuotedCsv(row.row_raw,{
     recordFraming:'CONFIRMED_SINGLE_CSV_RECORD',headerRaw:row.header_raw});
   const found=named.namedClaims.map(x=>({...x,decoded_value:x.value,start_byte:x.startByte,
     end_byte:x.endByte}));
   nameAfter.events++;nameAfter.expected+=reference.length;
   nameAfter.reviewOnly+=Number(named.disposition==='REVIEW_ONLY_NAMED');
   let tp=0,fp=0;
   for(const expect of reference){
     const candidates=found.filter(x=>x.name===expect.name);
     if(candidates.some(x=>x.decoded_value===expect.decoded_value&&
       x.start_byte===expect.start_byte&&x.end_byte===expect.end_byte))tp++;
     else if(candidates.length)fp++;
   }
   nameAfter.TP+=tp;nameAfter.FP+=fp;nameAfter.FN+=reference.length-tp;
   nameAfter.exactEvents+=Number(tp===reference.length&&fp===0);
   nameBefore.events++;nameBefore.expected+=reference.length;nameBefore.FN+=reference.length;
   continue;
 }
 if(row.status!=='POSITIONAL_SCORABLE')throw Error('Unknown frozen CSV eligibility status');
 const reference=row.expected as Cell[];
 for(const cell of reference)
   if(original.subarray(cell.start_byte,cell.end_byte).toString('utf8')!==cell.raw_span)
     throw Error('Independent byte-position oracle drift');
 const strata=byCategory[category(row)]??={before:empty(),after:empty()};
 const t0=performance.now();
 const legacy=scanDelimitedRow(row.raw,0,'comma');
 const played=legacy&&replayCandidate(legacy);
 const oldFields=played&&legacy?.naming==='positional'?legacy.fields.map((x,i)=>({
   ordinal:i,value:x.value,startByte:x.rawValueSpan.startByte,endByte:x.rawValueSpan.endByte})):[];
 const t1=performance.now();
 const result=inspectIndependentQuotedCsv(row.raw,{
   recordFraming:'CONFIRMED_SINGLE_CSV_RECORD',treatUnquotedEmptyAsNull:true});
 const t2=performance.now();
 add(before,reference,oldFields,oldFields.length>0,t1-t0);
 add(strata.before,reference,oldFields,oldFields.length>0,t1-t0);
 add(after,reference,result.positionalClaims,result.disposition==='REVIEW_ONLY_POSITIONAL',t2-t1);
 add(strata.after,reference,result.positionalClaims,result.disposition==='REVIEW_ONLY_POSITIONAL',t2-t1);
 after.rawDrift+=Number(result.raw!==row.raw||result.sourceBytes!==original.length);
 after.autoPromotion+=Number(result.autoPromoted||result.independentOracleCertified||result.nativeVerified);
 after.branchOver8+=Number(result.branchAttempts>8);
 const unqualified=inspectIndependentQuotedCsv(row.raw);
 unqualifiedCsvPromotions+=Number(unqualified.positionalClaims.length>0||
   unqualified.namedClaims.length>0||unqualified.autoPromoted);
}
function publicMetric(m:Metric){
 const lat=[...m.latencyMs].sort((a,b)=>a-b);
 const p95=lat[Math.floor((lat.length-1)*0.95)]??0;
 const {latencyMs,...rest}=m;
 return {...rest,p95ms:Number(p95.toFixed(3))};
}
const out={status:'QUALIFIED_FROZEN_CSV_SOURCE_COMPARISON',
  sourceSha:sha(source),goldenSha:sha(oracle),
  positional:{before:publicMetric(before),candidate:publicMetric(after)},
  sourceNamedHeaderSession:{before:publicMetric(nameBefore),candidate:publicMetric(nameAfter)},
  byCategory:Object.fromEntries(Object.entries(byCategory).map(([key,v])=>[key,{
    before:publicMetric(v.before),candidate:publicMetric(v.after)}])),
  invalidProfileOnly:profileInvalid,invalidVetoEscapes:profileVetoEscapes,
  unqualifiedCsvPromotions,certifiedSourceCompleteness:false,nativeVerified:false,
  scope:'CSV positional UTF8 decoded lexical cell triples separate from source header-name triples'};
console.log('INDEPENDENT_QUOTED_CSV '+JSON.stringify(out));
if(before.events!==meta.positional_events||before.expected!==meta.positional_value_utf8_span_triples||
   after.TP<=before.TP||after.FP>before.FP||after.rawDrift||after.autoPromotion||
   after.branchOver8||profileVetoEscapes||unqualifiedCsvPromotions||
   nameAfter.TP!==meta.named_source_triples||nameAfter.FP)
  process.exitCode=1;
