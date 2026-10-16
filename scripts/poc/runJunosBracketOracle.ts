import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';

type Event={id:string;source:string;raw:string};
const root=process.env.PARSER_STUDIO_FRESH_HOLDOUT_DIR ??
  path.join(os.homedir(),'.local/state/parserstudio-fresh-vendor-holdout-20261016');
const records=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as Event[];
const oracle=JSON.parse(fs.readFileSync(path.join(root,'junos_bracket_oracle.json'),'utf8')) as {
  oracle:Record<string,Record<string,string>>;unscannable:string[];
};
const negatives=JSON.parse(fs.readFileSync(path.join(root,'junos_bracket_mutations.json'),'utf8')) as Event[];

let total=0,structured=0,sourceSpecific=0,oracleExact=0,oracleMissing=0,oracleMismatch=0;
let rawRetained=0,freeTextRejected=0,genericOnly=0;
const mismatchIds:string[]=[];
for(const event of records.filter(r=>r.source.startsWith('juniper_srx/log/'))){
  total++;
  const parsed=parseSecurityInput(event.raw);
  if(parsed.ok)structured++;
  if(parsed.ok&&parsed.source_raw===event.raw&&parsed.events[0]?.raw===event.raw)rawRetained++;
  const fields=parsed.ok?parsed.events[0]?.fields??{}:{};
  const attrs=fields.junos_sd as Record<string,string>|undefined;
  if(attrs)sourceSpecific++;
  else if(parsed.ok)genericOnly++;
  if(event.source.endsWith('test-system.log')&&!parsed.ok)freeTextRejected++;
  const expected=oracle.oracle[event.id];
  if(!expected)continue;
  if(!attrs){oracleMissing++;if(mismatchIds.length<12)mismatchIds.push(event.id+':no_source_leaf');}
  else if(Object.keys(expected).length!==Object.keys(attrs).length||
      Object.entries(expected).some(([key,value])=>attrs[key]!==value)){
    oracleMismatch++;if(mismatchIds.length<12)mismatchIds.push(event.id+':changed_value');
  }else oracleExact++;
}
const acceptedIds:string[]=[];
let acceptedNegatives=0;
for(const event of negatives){
  const result=parseSecurityInput(event.raw);
  if(result.ok){
    acceptedNegatives++;
    if(acceptedIds.length<12)acceptedIds.push(event.id);
  }
}
const summary={events:total,structured,sourceSpecific,genericOnly,
  oracleRows:Object.keys(oracle.oracle).length,oracleExact,oracleMissing,oracleMismatch,
  notIndependentlyScannable:oracle.unscannable.length,rawRetained,freeTextRejected,
  malformedEvents:negatives.length,malformedRejected:negatives.length-acceptedNegatives,
  malformedAccepted:acceptedNegatives,mismatchIds,acceptedIds};
console.log('JUNOS_BRACKET_QUALIFICATION '+JSON.stringify(summary));
const qualified=total===105&&structured===81&&sourceSpecific===69&&genericOnly===12&&
  Object.keys(oracle.oracle).length===69&&oracleExact===69&&oracleMissing===0&&oracleMismatch===0&&
  oracle.unscannable.length===36&&rawRetained===81&&freeTextRejected===13&&
  negatives.length===414&&acceptedNegatives===0;
if(!qualified){process.exitCode=1;console.error('Junos bracket/source-fidelity qualification drift');}
