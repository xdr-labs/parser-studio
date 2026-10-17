/** Historical next-stage score of independently pinned third-party Go conformance.
 * Unlike a new blind experiment, this source has already been inspected in PR #46.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateSourceBody} from '../../src/poc/boundedSourceBodyArbiter';
const sha=(x:Buffer|string)=>crypto.createHash('sha256').update(x).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-external-syslog-20261017');
const manifest=fs.readFileSync(path.join(root,'sources.pinned.json'));
const reference=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v2.pinned.json'),'utf8'));
const records=fs.readFileSync(path.join(root,'golden-source-expected.v2.json'));
if(sha(manifest)!==reference.source_pin_sha256||sha(records)!==reference.oracle_sha256)
  throw Error('Frozen independent reference or source pins drifted');
type Field={name:string;value:string;start_byte:number;end_byte:number};
type Row={id:string;family:string;status:string;raw:string;raw_sha256:string;
  raw_bytes:number;field_triples:Field[]};
const data=JSON.parse(records.toString('utf8')) as Row[];
if(data.length!==reference.original_events||data.reduce((v,r)=>v+r.field_triples.length,0)!==reference.source_triples)
  throw Error('Original independent reference denominator was changed');
const total={events:0,referenceFields:0,tp:0,fp:0,fn:0,exactEvents:0,
  reviewOnly:0,abstain:0,rawPreserved:0,bodyClaims:0,autoPromoted:0};
const groups:Record<string,typeof total>={};
const blank=():typeof total=>({events:0,referenceFields:0,tp:0,fp:0,fn:0,
  exactEvents:0,reviewOnly:0,abstain:0,rawPreserved:0,bodyClaims:0,autoPromoted:0});
for(const row of data){
  const stat=groups[row.family]??=blank();
  const counts=[total,stat];
  if(row.status!=='INDEPENDENT_UPSTREAM_FIELD_TRIPLES')continue;
  if(sha(Buffer.from(row.raw,'utf8'))!==row.raw_sha256||
     Buffer.byteLength(row.raw,'utf8')!==row.raw_bytes)
    throw Error('Original source byte SHA changed');
  const result=arbitrateSourceBody(row.raw);
  const original=Buffer.from(row.raw,'utf8');
  const found=new Map(result.envelopeFields.map(x=>[x.name,x]));
  let tp=0,fp=0,fn=0;
  for(const field of row.field_triples){
    const candidate=found.get(field.name);
    if(candidate?.value===field.value&&candidate.startByte===field.start_byte&&
       candidate.endByte===field.end_byte)tp++;
    else{fn++;if(candidate)fp++;}
  }
  const expected=new Set(row.field_triples.map(x=>x.name));
  for(const name of found.keys())if(!expected.has(name))fp++;
  for(const c of counts){
    c.events++;
    c.referenceFields+=row.field_triples.length;
    c.tp+=tp;c.fp+=fp;c.fn+=fn;
    c.exactEvents+=Number(tp===row.field_triples.length&&fp===0&&fn===0);
    c.reviewOnly+=Number(result.disposition.startsWith('REVIEW_ONLY'));
    c.abstain+=Number(result.disposition==='ABSTAIN_UNSAFE');
    c.rawPreserved+=Number(result.raw===row.raw);
    c.bodyClaims+=result.bodyClaims.length;
    c.autoPromoted+=Number(result.autoPromoted);
  }
  for(const claim of result.envelopeFields){
    if(original.subarray(claim.startByte,claim.endByte).toString('utf8')!==claim.rawSpanValue)
      throw Error('Source-span byte replay drift');
  }
}
const report={status:'POST_HOC_HELDOUT_REPLAY_NOT_FRESH_BLIND',
  referenceSha:reference.oracle_sha256,scope:'SOURCE_ENVELOPE_TRIPLES_ONLY',
  claimedNativeSuccess:false,rawPublished:false,total,groups};
console.log('EXTERNAL_LAYERED_SOURCE '+JSON.stringify(report));
if(total.events!==5||total.referenceFields!==38||
   total.tp!==31||total.fp!==0||total.fn!==7||
   total.exactEvents!==4||total.rawPreserved!==5||total.autoPromoted)
  process.exitCode=1;
