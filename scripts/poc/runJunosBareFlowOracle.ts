import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';

type Event={id:string;source:string;raw:string};
const root=process.env.PARSER_STUDIO_FRESH_HOLDOUT_DIR ??
  path.join(os.homedir(),'.local/state/parserstudio-fresh-vendor-holdout-20261016');
const rows=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as Event[];
const oracle=JSON.parse(fs.readFileSync(path.join(root,'junos_bare_oracle.json'),'utf8')) as Record<string,Record<string,string>>;
const mutations=JSON.parse(fs.readFileSync(path.join(root,'junos_bare_mutations.json'),'utf8')) as Event[];

let exact=0,missing=0,mismatched=0,sourceRawPreserved=0;
const badIds:string[]=[];
for(const row of rows){
  const values=oracle[row.id];
  if(!values)continue;
  const result=parseSecurityInput(row.raw);
  const fields=result.ok?result.events[0]?.fields??{}:{};
  const extracted=fields.juniper_flow_kv as Record<string,string>|undefined;
  if(!extracted){
    missing++;
    badIds.push(row.id+':missing');
    continue;
  }
  if(Object.keys(values).length!==Object.keys(extracted).length||
     Object.entries(values).some(([name,value])=>extracted[name]!==value)){
    mismatched++;
    badIds.push(row.id+':mismatch');
    continue;
  }
  exact++;
  if(result.ok&&result.source_raw===row.raw&&result.events[0]?.raw===row.raw&&
     (fields.juniper as Record<string,unknown>|undefined)?.source_raw===row.raw)
    sourceRawPreserved++;
}
let badAccepted=0;
for(const mutated of mutations){
  if(parseSecurityInput(mutated.raw).ok){
    badAccepted++;
    if(badIds.length<12)badIds.push(mutated.id+':invalid_accepted');
  }
}
const summary={oracleRows:Object.keys(oracle).length,exact,missing,mismatched,
  sourceRawPreserved,mutated:mutations.length,rejected:mutations.length-badAccepted,
  badAccepted,badIds};
console.log('JUNOS_BARE_BRACKET_QUALIFICATION '+JSON.stringify(summary));
if(Object.keys(oracle).length!==5||exact!==5||missing||mismatched||
  sourceRawPreserved!==5||mutations.length!==45||badAccepted)
    process.exitCode=1;
