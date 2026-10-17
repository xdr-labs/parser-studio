/** Independent third-party source-field conformance, original byte spans and explicit abstention. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {parseSyslogEnvelope} from '../../src/syslogEnvelope';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';

type Expected={name:string;value:string;type:'string';start_byte:number;end_byte:number};
type Case={id:string;family:string;status:string;raw?:string;
  raw_sha256?:string;raw_bytes?:number;field_triples:Expected[]};
type Metric={events:number;referenceFields:number;exactEvents:number;tp:number;fp:number;fn:number;
  incorrectValue:number;incorrectSpan:number;sourceRawRetained:number;
  reviewOnly:number;abstain:number;baselineProductOk:number;
  unsafeAutoPromotions:number;unsupportedOrUnscorable:number};
const init=():Metric=>({events:0,referenceFields:0,exactEvents:0,tp:0,fp:0,fn:0,
  incorrectValue:0,incorrectSpan:0,sourceRawRetained:0,reviewOnly:0,abstain:0,
  baselineProductOk:0,unsafeAutoPromotions:0,unsupportedOrUnscorable:0});
const digest=(b:Buffer|string)=>crypto.createHash('sha256').update(b).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-external-syslog-20261017');
const manifest=fs.readFileSync(path.join(root,'sources.pinned.json'));
const meta=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v2.pinned.json'),'utf8'));
const records=fs.readFileSync(path.join(root,'golden-source-expected.v2.json'));
if(digest(manifest)!==meta.source_pin_sha256||digest(records)!==meta.oracle_sha256||
  meta.freeze!=='BEFORE_CANDIDATE_OR_BASELINE_SCORE')
  throw Error('Independent third-party source or expected golden identity drifted');
const examples=JSON.parse(records.toString('utf8')) as Case[];
if(examples.length!==meta.original_events||
  examples.reduce((v,x)=>v+x.field_triples.length,0)!==meta.source_triples)
  throw Error('Third-party conformance denominator drifted');
const baseline=init(),candidate=init();
const byFamily:Record<string,{baseline:Metric;candidate:Metric}>={};
const makeBaseline=(raw:string):Map<string,string>=>{
  const envelope=parseSyslogEnvelope(raw);
  const values=new Map<string,string>();
  if(!envelope)return values;
  for(const field of ['pri','version','month','day','time','timestamp','hostname',
    'appname','procid','msgid','message'] as const){
    const value=envelope[field];
    if(value!==undefined&&value!=='')values.set(field,String(value));
  }
  if(envelope.structuredData!==undefined)
    values.set('structured_data_raw',envelope.structuredData);
  return values;
};
function score(row:Case,which:'baseline'|'candidate'):Metric{
  const r=init();r.events++;
  if(row.status!=='INDEPENDENT_UPSTREAM_FIELD_TRIPLES'){
    r.unsupportedOrUnscorable++;return r;
  }
  if(!row.raw||digest(Buffer.from(row.raw,'utf8'))!==row.raw_sha256||
    Buffer.byteLength(row.raw,'utf8')!==row.raw_bytes)
    throw Error('Pre-frozen source bytes have changed');
  const expected=new Map(row.field_triples.map(f=>[f.name,f]));
  r.referenceFields=row.field_triples.length;
  const result=which==='baseline'?null:inspectGeneralSyslogEnvelope(row.raw);
  const values=which==='baseline'?makeBaseline(row.raw):
    new Map((result?.fields??[]).map(f=>[f.name,f.value]));
  r.reviewOnly+=Number(!!result&&result.disposition==='REVIEW_ONLY');
  r.abstain+=Number(!!result&&result.disposition!=='REVIEW_ONLY');
  r.unsafeAutoPromotions+=Number(result?.autoPromoted??false);
  r.sourceRawRetained+=Number(!result||result.originalRaw===row.raw);
  r.baselineProductOk+=Number(which==='baseline'&&parseSecurityInput(row.raw).ok);
  let exact=true;
  for(const [key,reference] of expected){
    const actual=values.get(key);
    if(actual===reference.value){
      if(which==='candidate'){
        const source=(result?.fields??[]).find(f=>f.name===key);
        if(source&&source.startByte===reference.start_byte&&
          source.endByte===reference.end_byte)r.tp++;
        else{r.fp++;r.fn++;r.incorrectSpan++;exact=false;}
      }else r.tp++;
    }else{
      r.fn++;
      if(actual!==undefined){r.fp++;r.incorrectValue++;}
      exact=false;
    }
  }
  for(const key of values.keys())if(!expected.has(key)){r.fp++;exact=false;}
  r.exactEvents+=Number(exact&&values.size===expected.size&&
    (which==='baseline'||result?.disposition==='REVIEW_ONLY'));
  return r;
}
function combine(to:Metric,from:Metric):void{
  for(const key of Object.keys(to) as (keyof Metric)[])to[key]+=from[key];
}
for(const example of examples){
  const b=score(example,'baseline'),c=score(example,'candidate');
  combine(baseline,b);combine(candidate,c);
  const group=byFamily[example.family]??={baseline:init(),candidate:init()};
  combine(group.baseline,b);combine(group.candidate,c);
}
const output={referenceSha:meta.oracle_sha256,qualification:'UPSTREAM_CONFORMANCE_FIELD_VALUES_NOT_NATIVE_STELLAR',
  scoring:'source_name_value_UTF8_byte_span_not_profile_semantics',
  baseline,candidate,byFamily};
const serialized=JSON.stringify(output,null,2)+'\n';
const target=path.join(root,'frozen-source-comparison.json');
if(fs.existsSync(target)&&fs.readFileSync(target,'utf8')!==serialized)
  throw Error('Cannot mutate a recorded independent comparison');
if(!fs.existsSync(target))fs.writeFileSync(target,serialized,{mode:0o600,flag:'wx'});
console.log('EXTERNAL_SYSLOG_COMPARISON '+JSON.stringify(output));
if(candidate.unsafeAutoPromotions||candidate.sourceRawRetained!==candidate.events-
   candidate.unsupportedOrUnscorable)process.exitCode=1;
