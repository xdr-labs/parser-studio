/** Sealed independent publisher CSV baseline: separated positional and named-triple rates. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateIndependentLeef} from '../../src/poc/independentLeefSource';
import {scanDelimitedRow} from '../../src/poc/losslessLexer';
import {replayCandidate} from '../../src/poc/grammarFunnel';
const root=path.join(os.homedir(),'.local/state/parserstudio-independent-quoted-csv-20261017');
const sha=(x:Buffer)=>crypto.createHash('sha256').update(x).digest('hex');
const source=fs.readFileSync(path.join(root,'sources.pinned.json'));
const oracle=fs.readFileSync(path.join(root,'author-expected-original-csv.v1.json'));
const meta=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v1.pinned.json'),'utf8'));
if(meta.stage!=='FROZEN_BEFORE_ANY_PRODUCT_BASELINE_OR_POC_SCORE'||
   meta.oracle_sha256!=='21df0514536935d5361e73b5cfbc4a263f8eb796caf27e4214e380d38a29427b'||
   sha(oracle)!==meta.oracle_sha256||sha(source)!==meta.source_pin_sha256)
  throw Error('Original CSV source or independently asserted golden drift');
type Cell={ordinal:number;decoded_value:string|null;start_byte:number;end_byte:number;raw_span:string};
type Row={id:string;status:string;raw:string;raw_sha256:string;raw_bytes:number;
  expected:Cell[];header_raw?:string;header_sha256?:string;row_raw?:string;row_sha256?:string};
type Metric={events:number;triples:number;tp:number;fp:number;fn:number;
  exactEvents:number;lexicalCandidates:number;abstained:number;byteDrift:number;
  autoPromotions:number;unknownNamedClaims:number};
const init=():Metric=>({events:0,triples:0,tp:0,fp:0,fn:0,exactEvents:0,
  lexicalCandidates:0,abstained:0,byteDrift:0,autoPromotions:0,unknownNamedClaims:0});
const old=init(),qualified=init(),byCategory:Record<string,Metric>={};
const rows=JSON.parse(oracle.toString('utf8')) as Row[];
if(rows.length!==meta.originals)throw Error('Original CSV source count drift');
const makeKey=(r:Row)=>{
  if(r.raw.includes('\r')||r.raw.includes('\n'))return 'embedded_newline';
  if(r.raw.includes('""'))return 'doubled_quotes';
  if(r.expected.some(x=>x.decoded_value===null))return 'empty_unquoted';
  if(r.expected.length<3)return 'one_or_two_columns';
  if(r.raw.includes('"'))return 'quoted';
  return 'plain_three_plus';
};
for(const row of rows){
 const b=Buffer.from(row.raw,'utf8');
 if(sha(b)!==row.raw_sha256||b.length!==row.raw_bytes)throw Error('Original CSV byte identity drift');
 if(row.status!=='POSITIONAL_SCORABLE')continue;
 const group=byCategory[makeKey(row)]??=init();
 const before=arbitrateIndependentLeef(row.raw);
 if(before.autoPromoted||before.nativeVerified||before.independentOracleCertified)
   throw Error('Preceding stage unexpectedly auto-certified CSV input');
 old.events++;old.triples+=row.expected.length;old.fn+=row.expected.length;
 qualified.events++;qualified.triples+=row.expected.length;
 group.events++;group.triples+=row.expected.length;
 for(const cell of row.expected){
   if(b.subarray(cell.start_byte,cell.end_byte).toString('utf8')!==cell.raw_span)
     throw Error('Golden byte range moved');
 }
 const candidate=scanDelimitedRow(row.raw,0,'comma');
 const played=candidate&&replayCandidate(candidate);
 const fields=played&&candidate?.naming==='positional'?candidate.fields:[];
 qualified.lexicalCandidates+=Number(fields.length>0);
 qualified.abstained+=Number(fields.length===0);
 group.lexicalCandidates+=Number(fields.length>0);
 group.abstained+=Number(fields.length===0);
 let tp=0,fp=0;
 for(const x of row.expected){
   const c=fields[x.ordinal];
   if(c&&c.value===x.decoded_value&&
       c.rawValueSpan.startByte===x.start_byte&&c.rawValueSpan.endByte===x.end_byte)
     tp++;
   else if(c)fp++;
 }
 const extra=Math.max(0,fields.length-row.expected.length);
 fp+=extra;
 qualified.tp+=tp;qualified.fp+=fp;qualified.fn+=row.expected.length-tp;
 group.tp+=tp;group.fp+=fp;group.fn+=row.expected.length-tp;
 qualified.exactEvents+=Number(tp===row.expected.length&&fp===0);
 group.exactEvents+=Number(tp===row.expected.length&&fp===0);
}
const named=rows.filter(x=>x.status==='SOURCE_NAMED_HEADER_SESSION');
if(named.length!==meta.source_named_sessions)throw Error('Original header-name cohort changed');
for(const pair of named){
 if(!pair.header_raw||!pair.row_raw||sha(Buffer.from(pair.header_raw,'utf8'))!==pair.header_sha256||
    sha(Buffer.from(pair.row_raw,'utf8'))!==pair.row_sha256)throw Error('Publisher separate header/row originals drifted');
}
const result={status:'FROZEN_CSV_BASELINE_EVIDENCE_ONLY',
 oracleSha:sha(oracle),sourceSha:sha(source),scoredPositionalEvents:qualified.events,
 positionalTriples:qualified.triples,unchangedSourceObserver:old,
 existingQualifiedPositionalLexer:qualified,byCategory,
 independentlyPublisherNamedSessions:named.length,independentlyNamedFields:meta.named_source_triples,
 candidateSourceNamedTriples:0,
 nonClaim:'cell ordinals are not source column names; no product/native verified success'};
console.log('INDEPENDENT_QUOTED_CSV_BASELINE '+JSON.stringify(result));
if(qualified.events!==meta.positional_events||qualified.triples!==meta.positional_value_utf8_span_triples||
   qualified.byteDrift||qualified.autoPromotions)process.exitCode=1;
