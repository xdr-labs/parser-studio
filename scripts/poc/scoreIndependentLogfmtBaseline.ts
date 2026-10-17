/** Independent Go-publisher expected logfmt source field byte oracle, original-only. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateOptionalIndependentCsv} from '../../src/poc/independentQuotedCsvSource';
import {scanKeyValues} from '../../src/poc/losslessLexer';
import {replayCandidate} from '../../src/poc/grammarFunnel';
const root=path.join(os.homedir(),'.local/state/parserstudio-independent-logfmt-20261017');
const sha=(buf:Buffer)=>crypto.createHash('sha256').update(buf).digest('hex');
const sources=fs.readFileSync(path.join(root,'sources.pinned.json'));
const truth=fs.readFileSync(path.join(root,'independent-expected-fields.v1.json'));
const meta=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v1.pinned.json'),'utf8'));
if(meta.stage!=='SEALED_BEFORE_ANY_CANDIDATE_SCORING'||
   meta.oracle_sha256!=='1dc71e3d28513c9f8a46f918c2d8b938406942a18a45e4faca203908283ec4d8'||
   sha(truth)!==meta.oracle_sha256||sha(sources)!==meta.source_pin_sha256)
  throw Error('Independent logfmt original/expected frozen reference drifted');
type Golden={name:string;ordinal:number;value:string;raw_span:string;
  start_byte:number;end_byte:number};
type Row={status:string;publisher:string;raw:string;raw_sha256:string;
  raw_bytes:number;field_goldens:Golden[];message_record_framing:string};
const rows=JSON.parse(truth.toString('utf8')) as Row[];
if(rows.length!==meta.case_count)throw Error('Publisher original fixture count drifted');
type Score={events:number;triples:number;tp:number;fp:number;fn:number;
  exactEvents:number;sourceExtraUnscored:number;rawRetained:number;
  autoPromoted:number;reviewOnly:number;abstain:number;noClaims:number};
const zero=():Score=>({events:0,triples:0,tp:0,fp:0,fn:0,exactEvents:0,
  sourceExtraUnscored:0,rawRetained:0,autoPromoted:0,reviewOnly:0,
  abstain:0,noClaims:0});
const old=zero(),lexer=zero(),groups:Record<string,{old:Score;lexer:Score}>={};
for(const row of rows){
 if(row.status!=='SCORABLE_PARTIAL')continue;
 const original=Buffer.from(row.raw,'utf8');
 if(sha(original)!==row.raw_sha256||original.length!==row.raw_bytes)
   throw Error('Upstream original logfmt bytes changed');
 for(const g of row.field_goldens)
   if(original.subarray(g.start_byte,g.end_byte).toString('utf8')!==g.raw_span)
     throw Error('Upstream expected original UTF8 source span drifted');
 const before=arbitrateOptionalIndependentCsv(row.raw);
 if(!('bodyClaims' in before))throw Error('Unexpected qualified parser result for unprofiled logfmt');
 const rawClaims=[...before.envelopeFields,...before.bodyClaims];
 const scan=scanKeyValues(row.raw,0,'space',{preserveRepeated:true});
 const checked=scan&&replayCandidate(scan);
 const lexClaims=checked&&scan?.naming==='source'?scan.fields.map(f=>({
   name:f.key,value:f.value,startByte:f.rawValueSpan.startByte,endByte:f.rawValueSpan.endByte})):[];
 const bySource=groups[row.publisher]??={old:zero(),lexer:zero()};
 for(const [metric,claims,stage] of [[old,rawClaims,'old'],[bySource.old,rawClaims,'old'],
   [lexer,lexClaims,'lexer'],[bySource.lexer,lexClaims,'lexer']] as const){
   metric.events++;metric.triples+=row.field_goldens.length;
   metric.rawRetained++;
   metric.reviewOnly+=Number(claims.length>0);
   metric.noClaims+=Number(claims.length===0);
   let tp=0,fp=0;
   for(const reference of row.field_goldens){
     const withName=claims.filter(c=>c.name===reference.name);
     const winner=withName.find(c=>String(c.value)===reference.value&&
       c.startByte===reference.start_byte&&c.endByte===reference.end_byte);
     if(winner)tp++;
     else if(withName.length)fp+=withName.length;
   }
   metric.tp+=tp;metric.fp+=fp;metric.fn+=row.field_goldens.length-tp;
   metric.exactEvents+=Number(tp===row.field_goldens.length&&fp===0);
   metric.sourceExtraUnscored+=claims.filter(c=>
     !row.field_goldens.some(g=>g.name===c.name)).length;
 }
 old.autoPromoted+=Number(before.autoPromoted||before.nativeVerified||
  before.independentOracleCertified);
}
const score={status:'PRE_FROZEN_LOGFMT_SOURCE_BASELINE',
  originalSha:sha(truth),sourceSha:sha(sources),
  eligiblePartialMessages:meta.scorable_partial_messages,
  independentlyNamedTriples:meta.source_name_value_utf8_triples,
  precedingSourceObserver:old,existingQualifiedStrictSpaceLexer:lexer,
  byPublisher:groups,
  unverified:'no source/native certification; source-value-less nil/bare fields explicitly excluded'};
console.log('INDEPENDENT_LOGFMT_BASELINE '+JSON.stringify(score));
if(old.events!==meta.scorable_partial_messages||old.triples!==meta.source_name_value_utf8_triples||
   old.autoPromoted||lexer.autoPromoted)process.exitCode=1;
