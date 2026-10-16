import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {parseSecurityInput} from '../../src/securityInputPipeline';

type Event={id:string;source:string;raw:string};
type Oracle={kind:'pan'|'umbrella';values:string[];offset:number};
const root=process.env.PARSER_STUDIO_PUBLIC_HOLDOUT_DIR ??
  path.join(os.homedir(),'.local/state/parserstudio-ext-holdout-20261016');
const events=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as Event[];
const oracle=JSON.parse(fs.readFileSync(path.join(root,'csv_oracle.json'),'utf8')) as Record<string,Oracle>;
const negative=JSON.parse(fs.readFileSync(path.join(root,'adversarial.json'),'utf8')) as Event[];

function flatten(value:unknown):string[]{
  if(value===null||value===undefined)return [];
  if(Array.isArray(value))return value.flatMap(flatten);
  if(typeof value==='object')return Object.entries(value as Record<string,unknown>).flatMap(([key,val])=>
    /^(source_raw|raw|message_raw|raw_lines|rawRecords|original|source_index)$/i.test(key) ?
      []:flatten(val));
  return [String(value)];
}

function extractColumns(fields:Record<string,unknown>):string[]|null{
  const generic=fields.generic as Record<string,unknown>|undefined;
  const columns=generic?.columns;
  if(!columns||typeof columns!=='object'||Array.isArray(columns))return null;
  const named=columns as Record<string,unknown>;
  const keys=Object.keys(named);
  if(!keys.every((key,index)=>key==='column_'+index))return null;
  return Object.values(named).map(value=>String(value??''));
}

let structured=0;
let oracleExact=0;
let missing=0;
let valueMismatch=0;
let jsonEvents=0;
let jsonExpected=0;
let jsonRecovered=0;
let jsonFailures=0;
const byFamily=new Map<string,{total:number;structured:number;csvReference:number;csvExact:number}>();
const firstFailures:string[]=[];
for(const event of events){
  const family=event.source.split('/').slice(0,2).join('/');
  if(!byFamily.has(family))byFamily.set(family,{total:0,structured:0,csvReference:0,csvExact:0});
  const group=byFamily.get(family)!;
  group.total++;
  const result=parseSecurityInput(event.raw);
  if(result.ok){structured++;group.structured++;}
  const fields=(result.ok?result.events[0]?.fields:{})??{};
  const reference=oracle[event.id];
  if(reference){
    group.csvReference++;
    const columns=extractColumns(fields);
    if(!columns){missing++;if(firstFailures.length<12)firstFailures.push(event.id+':missing');}
    else if(columns.length!==reference.values.length||
      columns.some((value,index)=>value!==reference.values[index])){
      valueMismatch++;if(firstFailures.length<12)firstFailures.push(event.id+':column_mismatch');
    }else{oracleExact++;group.csvExact++;}
  }
  if(event.source.includes('defender')){
    jsonEvents++;
    let parsed:unknown;
    try{parsed=JSON.parse(event.raw);}catch{jsonFailures++;continue;}
    const sourceValues=flatten(parsed);
    const extractedValues=flatten(fields);
    jsonExpected+=sourceValues.length;
    for(const value of sourceValues){
      const pos=extractedValues.indexOf(value);
      if(pos<0){jsonFailures++;if(firstFailures.length<12)firstFailures.push(event.id+':lost_json_value');}
      else{jsonRecovered++;extractedValues.splice(pos,1);}
    }
    if(!result.ok){jsonFailures++;if(firstFailures.length<12)firstFailures.push(event.id+':no_json_event');}
  }
}

const acceptedIds:string[]=[];
let acceptedMutations=0;
for(const event of negative){
  if(parseSecurityInput(event.raw).ok){
    acceptedMutations++;
    if(acceptedIds.length<12)acceptedIds.push(event.id);
  }
}
const corruptCount=negative.length-acceptedMutations;
const summary={
  raw_corpus_sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'records.json'))).digest('hex'),
  events:events.length,
  structured,
  csvOracleRows:Object.keys(oracle).length,
  csvExact:oracleExact,
  csvMissing:missing,
  csvValueMismatch:valueMismatch,
  defenderJsonEvents:jsonEvents,
  defenderScalarSourceValues:jsonExpected,
  defenderScalarRecovered:jsonRecovered,
  defenderLosses:jsonFailures,
  mutatedInputs:negative.length,
  rejectedMutations:corruptCount,
  acceptedMutations,
  groups:Object.fromEntries(byFamily),
  firstFailures,
  firstAcceptedMutations:acceptedIds,
};
console.log('PUBLIC_SECURITY_HOLDOUT_QUALIFICATION '+JSON.stringify(summary));
const qualified=events.length===790&&structured===777&&
  Object.keys(oracle).length===766&&oracleExact===758&&missing===8&&valueMismatch===0&&
  jsonEvents===17&&jsonExpected===675&&jsonRecovered===675&&jsonFailures===0&&
  negative.length===1532&&acceptedMutations===0;
if(!qualified){process.exitCode=1;console.error('Holdout qualification changed: inspect the current source evidence');}
