/** Independent pinned upstream Go Syslog expectation vs unchanged parsing paths.
 *
 * Source byte spans are NOT exposed by baseline and must never be invented.
 * Semantic/native parsing, lexical success and source fidelity are separate.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {parseSyslogEnvelope} from '../../src/syslogEnvelope';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {inspectGrammarFunnel} from '../../src/poc/grammarFunnel';

type Truth={name:string;type:'string';value:string;start_byte:number;end_byte:number};
type Row={id:string;source_id:string;split:string;status:string;upstream_accepts?:boolean;
  raw?:string|null;raw_sha256?:string;raw_bytes?:number;fields:Truth[];
  expected_grammar?:string};
type Score={all:number;scorable:number;negative:number;unscorable:number;sourceFields:number;
  envelopeAccepted:number;envelopeRejected:number;exactValueEvents:number;tp:number;fp:number;fn:number;
  negativeEnvelopeAccepts:number;negativeProductOk:number;negativeFunnelSelected:number;
  scorableProductOk:number;scorableRawPreserved:number;
  missingSpanContract:number;invalidOriginalByteIdentity:number;unexpectedExceptions:number};
const blank=():Score=>({all:0,scorable:0,negative:0,unscorable:0,sourceFields:0,
  envelopeAccepted:0,envelopeRejected:0,exactValueEvents:0,tp:0,fp:0,fn:0,
  negativeEnvelopeAccepts:0,negativeProductOk:0,negativeFunnelSelected:0,
  scorableProductOk:0,scorableRawPreserved:0,missingSpanContract:0,
  invalidOriginalByteIdentity:0,unexpectedExceptions:0});
const sha=(x:Buffer|string)=>crypto.createHash('sha256').update(x).digest('hex');
const root=path.join(os.homedir(),'.local/state/parserstudio-syslog-conformance-20261017');
const mode=process.argv[2]??'development';
if(mode!=='development'&&mode!=='sealed')throw Error('Explicit original split required');
const pins=fs.readFileSync(path.join(root,'sources.pinned.json'));
const summary=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.v3.pinned.json'),'utf8'));
const raw=fs.readFileSync(path.join(root,'records-and-expected.v3.pinned.json'));
if(sha(pins)!==summary.source_manifest_sha256||
   sha(raw)!==summary.private_oracle_sha256||
   summary.stage!=='FROZEN_BEFORE_ANY_BASELINE_OR_CANDIDATE_SCORING')
  throw Error('Independent source corpus not pre-frozen');
const data=JSON.parse(raw.toString('utf8')) as Row[];
if(data.length!==summary.all_cases||
   data.reduce((v,r)=>v+r.fields.length,0)!==summary.source_field_triples)
  throw Error('Independent original denominator changed');
const total=blank();
const groups:Record<string,Score>={};
const add=(to:Score,from:Score)=>{
  for(const k of Object.keys(from) as (keyof Score)[])to[k]+=from[k];
};
for(const row of data){
  if(row.split!==mode)continue;
  const one=blank();one.all++;
  if(row.status==='UNSCORABLE')one.unscorable++;
  else if(row.status==='NEGATIVE_ONLY')one.negative++;
  else{
    one.scorable++;
    one.sourceFields+=row.fields.length;
    one.missingSpanContract++;
  }
  if(row.raw!=null){
    const original=Buffer.from(row.raw,'utf8');
    if(row.raw_sha256!==sha(original)||row.raw_bytes!==original.length){
      one.invalidOriginalByteIdentity++;throw Error('Pinned original bytes drifted');
    }
    const envelope=parseSyslogEnvelope(row.raw);
    one.envelopeAccepted+=Number(envelope!==null);
    one.envelopeRejected+=Number(envelope===null);
    const product=parseSecurityInput(row.raw);
    const funnel=inspectGrammarFunnel(row.raw,product.ok);
    if(row.status==='NEGATIVE_ONLY'){
      one.negativeEnvelopeAccepts+=Number(envelope!==null);
      one.negativeProductOk+=Number(product.ok);
      one.negativeFunnelSelected+=Number(!!funnel.selected);
    }
    if(row.status==='INDEPENDENT_UPSTREAM_CONFORMANCE_FIELDS'){
      one.scorableProductOk+=Number(product.ok);
      one.scorableRawPreserved+=Number(product.ok&&product.source_raw===row.raw);
      const byName=new Map(row.fields.map(f=>[f.name,f]));
      const observed=new Map<string,string>();
      if(envelope){
        for(const name of ['pri','version','timestamp','month','day','time',
          'hostname','appname','procid','msgid','message'] as const){
          if(envelope[name]!==undefined&&envelope[name]!=='')
            observed.set(name,String(envelope[name]));
        }
        if(envelope.structuredData!==undefined)
          observed.set('structured_data_raw',envelope.structuredData);
      }
      let same=0;
      for(const [name,field] of byName){
        if(observed.get(name)===field.value){one.tp++;same++;}
        else {one.fn++;if(observed.has(name))one.fp++;}
      }
      for(const name of observed.keys())if(!byName.has(name))one.fp++;
      one.exactValueEvents+=Number(
        same===row.fields.length&&observed.size===row.fields.length&&row.fields.length>0);
    }
  }
  add(total,one);
  const bucket=groups[row.source_id]??=blank();
  add(bucket,one);
}
const out={mode,reference_sha:summary.private_oracle_sha256,
  method:'UNMODIFIED_PRODUCT_ENVELOPE_AND_PIPELINE',
  sourceSpanMeasurement:'NOT_EXPOSED_NOT_SCORABLE',
  lexicalMatchIsNotComplete:'TRUE',total,groups};
const serialized=JSON.stringify(out,null,2)+'\n';
const dest=path.join(root,'baseline-'+mode+'.json');
if(fs.existsSync(dest)&&fs.readFileSync(dest,'utf8')!==serialized)
  throw Error('Frozen baseline observation differs');
if(!fs.existsSync(dest))fs.writeFileSync(dest,serialized,{mode:0o600,flag:'wx'});
console.log('SYSLOG_CONFORMANCE_BASELINE '+JSON.stringify(out));
if(total.invalidOriginalByteIdentity||total.unexpectedExceptions)
  process.exitCode=1;
