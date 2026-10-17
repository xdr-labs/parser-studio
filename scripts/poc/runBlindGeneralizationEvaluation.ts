/** Blind, private-field evaluator. No source values, names or raw bytes in output. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {inspectGrammarFunnel} from '../../src/poc/grammarFunnel';

type JsonField={path:string;value:unknown;type:'null'|'boolean'|'integer'|'number'|'string';
  value_start_byte:number;value_end_byte:number};
type EventRow={id:string;family:string;split:'development'|'sealed_holdout';
  raw_event_sha256:string;parent_file_sha256:string;parent_byte_start:number;
  parent_byte_end:number;format_hint:string;raw:string|null;fields:JsonField[];
  oracle_status:string;exclusion:string|null};
type SourceLeaf={path:string;type:string;value:unknown;start_byte?:number;end_byte?:number};
type Counts={events:number;scorable:number;excluded:number;referenceFields:number;
  baselineOk:number;baselineRawPreserved:number;baselineExactValueEvents:number;
  baselineValueTP:number;baselineValueFP:number;baselineValueFN:number;
  baselineUnsafeOk:number;invalidNumberRisk:number;
  baselineMissingSpanContract:number;grammaticalCandidateUnscorable:number;
  grammarAmbiguous:number;grammarRawOnly:number;unexpectedErrors:number};

const root=path.join(os.homedir(),'.local/state/parserstudio-generalization-blind-20261017');
const sha=(v:Buffer|string)=>crypto.createHash('sha256').update(v).digest('hex');
const mode=process.argv[2]??'development';
if(mode!=='development'&&mode!=='sealed_holdout')
  throw Error('Explicit development or sealed_holdout evaluation mode required');
const summaryBytes=fs.readFileSync(path.join(root,'oracle-summary.pinned.json'));
const manifest=JSON.parse(summaryBytes.toString('utf8')) as {
  private_oracle_sha256:string;status:string;all_events:number;
  source_manifest_sha256:string;scorable_events:number;leaf_fields:number};
if(manifest.status!=='FROZEN_BEFORE_BASELINE_OR_CANDIDATE_SCORING')
  throw Error('Independent golden source oracle was not frozen');
const sourceManifest=fs.readFileSync(path.join(root,'sources.pinned.json'));
if(sha(sourceManifest)!==manifest.source_manifest_sha256)
  throw Error('Source manifest changed after oracle freeze');
const bytes=fs.readFileSync(path.join(root,'frozen-records-and-oracle.json'));
if(sha(bytes)!==manifest.private_oracle_sha256)
  throw Error('Private golden source oracle changed after freeze');
const rows=JSON.parse(bytes.toString('utf8')) as EventRow[];
if(rows.length!==manifest.all_events||
  rows.filter(x=>x.oracle_status==='INDEPENDENT_JSON_BYTE_TRUTH').length!==manifest.scorable_events||
  rows.reduce((sum,row)=>sum+row.fields.length,0)!==manifest.leaf_fields)
  throw Error('Golden source denominator changed');

const blank=():Counts=>({events:0,scorable:0,excluded:0,referenceFields:0,baselineOk:0,
  baselineRawPreserved:0,baselineExactValueEvents:0,baselineValueTP:0,
  baselineValueFP:0,baselineValueFN:0,baselineUnsafeOk:0,
  invalidNumberRisk:0,baselineMissingSpanContract:0,
  grammaticalCandidateUnscorable:0,grammarAmbiguous:0,grammarRawOnly:0,
  unexpectedErrors:0});
const total=blank();
const byFamily:Record<string,Counts>={};
const copy=(from:Counts,to:Counts)=>{for(const key of Object.keys(from) as (keyof Counts)[])to[key]+=from[key];};
function flatten(value:unknown,pathKey='',out:SourceLeaf[]=[],depth=0):SourceLeaf[]{
  if(depth>24||out.length>2500)throw Error('Unsafe baseline field tree');
  if(Array.isArray(value)){value.forEach((item,i)=>flatten(item,pathKey+'/'+i,out,depth+1));return out;}
  if(value!==null&&typeof value==='object'){
    for(const [key,item] of Object.entries(value as Record<string,unknown>))
      flatten(item,pathKey+'/'+key.replaceAll('~','~0').replaceAll('/','~1'),out,depth+1);
    return out;
  }
  const type=value===null?'null':typeof value==='boolean'?'boolean':
    typeof value==='number'?(Number.isInteger(value)?'integer':'number'):typeof value;
  out.push({path:pathKey,type,value});
  return out;
}
function sameValue(actual:SourceLeaf,expected:JsonField,raw:string):boolean{
  if(actual.path!==expected.path||actual.type!==expected.type)return false;
  if(expected.type==='integer'){
    const token=Buffer.from(raw,'utf8').subarray(expected.value_start_byte,expected.value_end_byte).toString('utf8');
    return typeof actual.value==='number'&&Number.isInteger(actual.value)&&
      Number.isFinite(actual.value)&&String(actual.value)===token;
  }
  return Object.is(actual.value,expected.value);
}
function valueCounts(output:SourceLeaf[],reference:JsonField[],raw:string):{tp:number;fp:number;fn:number;exact:boolean}{
  const expected=new Map(reference.map(f=>[f.path,f]));
  const found=new Map(output.map(f=>[f.path,f]));
  let tp=0,fp=0,fn=0;
  for(const [name,field] of expected){
    const actual=found.get(name);
    if(actual&&sameValue(actual,field,raw))tp++;
    else{fn++;if(actual)fp++;}
  }
  for(const name of found.keys())if(!expected.has(name))fp++;
  return {tp,fp,fn,exact:reference.length>0&&tp===reference.length&&fp===0&&fn===0};
}
function evaluate(row:EventRow):Counts{
  const result=blank();
  result.events++;
  const raw=row.raw;
  if(raw===null||sha(Buffer.from(raw,'utf8'))!==row.raw_event_sha256)
    throw Error('Private event byte identity changed');
  const isOracle=row.oracle_status==='INDEPENDENT_JSON_BYTE_TRUTH';
  result.scorable+=Number(isOracle);
  result.excluded+=Number(!isOracle);
  result.referenceFields+=row.fields.length;
  const original=parseSecurityInput(raw);
  result.baselineOk+=Number(original.ok);
  result.baselineRawPreserved+=Number(original.ok&&original.source_raw===raw);
  const suggested=inspectGrammarFunnel(raw,original.ok);
  result.grammarAmbiguous+=Number(suggested.disposition==='ambiguous');
  result.grammarRawOnly+=Number(suggested.disposition==='raw_only');
  result.grammaticalCandidateUnscorable+=Number(!isOracle&&!!suggested.selected);
  if(!isOracle)return result;
  const unsafe=row.fields.some(f=>{
    if(f.type!=='integer')return false;
    const rawValue=Buffer.from(raw,'utf8').subarray(f.value_start_byte,f.value_end_byte).toString('utf8');
    return !Number.isSafeInteger(Number(rawValue));
  });
  result.invalidNumberRisk+=Number(unsafe);
  result.baselineMissingSpanContract++; // Baseline exposes no native original-field byte ranges.
  const body=original.ok?
    (original.kind==='single_event'&&original.events.length===1?original.events[0]?.fields:
      original.kind==='json_batch'&&original.events.every(e=>e.fields.body!==undefined)?
        {...((original.context?.container as Record<string,unknown>)??{}),Records:original.events.map(e=>e.fields.body)}:
        original.events.length===1?original.events[0]?.fields.body:undefined):undefined;
  let values:SourceLeaf[]=[];
  if(body!==undefined){
    try{values=flatten(body);}catch{result.unexpectedErrors++;return result;}
  }
  const compare=valueCounts(values,row.fields,raw);
  result.baselineValueTP+=compare.tp;
  result.baselineValueFP+=compare.fp;
  result.baselineValueFN+=compare.fn;
  result.baselineExactValueEvents+=Number(compare.exact);
  result.baselineUnsafeOk+=Number(original.ok&&!compare.exact);
  return result;
}
for(const row of rows){
  if(row.split!==mode)continue;
  const item=evaluate(row);
  copy(item,total);
  const by=byFamily[row.family]??=blank();
  copy(item,by);
}
const published={gate:'SOURCE_JSON_FIELD_VALUE_ONLY_NOT_STELLAR',mode,
  reference_manifest_sha:manifest.private_oracle_sha256,total,byFamily,
  position_metric_for_baseline:'NOT_EXPOSED_NOT_SCORABLE',
  unsafeOkLabel:'STRUCTURAL_OK_WITH_SOURCE_MISMATCH_NOT_NATIVE_FALSE_COMPLETE',
  unscorablePolicy:'UNSCORABLE_NOT_ASSUMED_CORRECT_OR_INCORRECT'};
const output=JSON.stringify(published,null,2)+'\n';
const dest=path.join(root,'baseline-v3-'+mode+'.json');
if(fs.existsSync(dest)&&fs.readFileSync(dest,'utf8')!==output)
  throw Error('Already-scored frozen baseline must not be silently replaced');
if(!fs.existsSync(dest))fs.writeFileSync(dest,output,{mode:0o600,flag:'wx'});
console.log('GENERALIZATION_BASELINE '+JSON.stringify(published));
if(total.baselineRawPreserved!==total.baselineOk||total.unexpectedErrors>0)
  process.exitCode=1;
