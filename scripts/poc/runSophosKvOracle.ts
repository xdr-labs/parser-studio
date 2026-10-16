import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';

type RecordSample={id:string;source:string;raw:string};
const root=process.env.PARSER_STUDIO_FRESH_HOLDOUT_DIR ??
  path.join(os.homedir(),'.local/state/parserstudio-fresh-vendor-holdout-20261016');
const records=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as RecordSample[];
const expected=JSON.parse(fs.readFileSync(path.join(root,'sophos_kv_oracle.json'),'utf8')) as {
  oracle:Record<string,Record<string,string>>;unscannable:string[];
};
const mutated=JSON.parse(fs.readFileSync(path.join(root,'sophos_kv_mutations.json'),'utf8')) as
  Array<{id:string;raw:string}>;

let total=0,structured=0,sourceSpecific=0,genericOnly=0,unparsed=0;
let independentEligible=0,exact=0,missing=0,mismatched=0,rawPreserved=0;
const sampleProblems:string[]=[];
for(const row of records.filter(row=>row.source.startsWith('sophos/xg/'))){
  total++;
  const parsed=parseSecurityInput(row.raw);
  const fields=parsed.ok?parsed.events[0]?.fields??{}:{};
  const sophos=fields.sophos as {variant?:string;fields?:Record<string,string>;source_raw?:string}|undefined;
  const direct=sophos?.fields;
  if(parsed.ok){
    structured++;
    if(direct){sourceSpecific++;if(sophos?.source_raw===row.raw)rawPreserved++;}
    else genericOnly++;
  }else unparsed++;
  const oracle=expected.oracle[row.id];
  if(oracle){
    independentEligible++;
    if(!direct){missing++;if(sampleProblems.length<8)sampleProblems.push(row.id+':no-qualified-leaf');}
    else if(Object.keys(direct).length!==Object.keys(oracle).length||
      Object.entries(oracle).some(([key,value])=>direct[key]!==value)){
      mismatched++;if(sampleProblems.length<8)sampleProblems.push(row.id+':different-value');
    }else exact++;
  }
}
let acceptedBad=0;
const badExamples:string[]=[];
for(const event of mutated){
  if(parseSecurityInput(event.raw).ok){
    acceptedBad++;
    if(badExamples.length<8)badExamples.push(event.id);
  }
}
const summary={events:total,structured,sourceSpecific,genericOnly,unparsed,
  independentOracleRows:independentEligible,exactValues:exact,missingQualifiedLeaf:missing,
  fieldValueMismatch:mismatched,sourceRawPreserved:rawPreserved,
  notIndependentlyScannable:expected.unscannable.length,
  malformedSourceVariants:mutated.length,malformedRejected:mutated.length-acceptedBad,
  malformedAccepted:acceptedBad,sampleProblems,badExamples};
console.log('SOPHOS_XG_SOURCE_QUALIFICATION '+JSON.stringify(summary));
const qualified=total===271&&structured===256&&sourceSpecific===150&&genericOnly===106&&unparsed===15&&
  independentEligible===151&&exact===150&&missing===1&&mismatched===0&&rawPreserved===150&&
  expected.unscannable.length===120&&mutated.length===900&&acceptedBad===0;
if(!qualified){process.exitCode=1;console.error('Sophos source-fidelity qualification drift');}
