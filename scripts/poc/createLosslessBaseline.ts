import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';
const root=path.join(os.homedir(),'.local/state/parserstudio-lossless-fresh-20261017');
const rawBytes=fs.readFileSync(path.join(root,'records.json'));
const rows=JSON.parse(rawBytes.toString('utf8')) as {id:string;source:string;raw:string}[];
const checks=rows.map(row=>{
  const result=parseSecurityInput(row.raw);
  return {id:row.id,source:row.source,ok:result.ok,kind:result.ok?result.kind:null,
    count:result.ok?result.events.length:0,
    rawRetained:result.ok?(result.source_raw===row.raw):false};
});
const group:Record<string,{events:number;parsed:number;rawPreserved:number}>={};
for(const row of checks){
  const vendor=row.source.split('/')[1]!;
  const f=group[vendor]??={events:0,parsed:0,rawPreserved:0};
  f.events++;if(row.ok)f.parsed++;if(row.rawRetained)f.rawPreserved++;
}
const baseline={base_sha:'6b4f125d01e8d90a9306ba64b1a2c46b1f84c863',
  records_sha256:crypto.createHash('sha256').update(rawBytes).digest('hex'),
  total:rows.length,parsed:checks.filter(x=>x.ok).length,
  rawPreserved:checks.filter(x=>x.rawRetained).length,groups:group,
  checks};
const output=path.join(root,'baseline.json');
if(fs.existsSync(output)){
  if(fs.readFileSync(output,'utf8')!==JSON.stringify(baseline))throw Error('baseline drift');
}else{fs.writeFileSync(output,JSON.stringify(baseline),{mode:0o600});}
console.log('FROZEN_BASELINE '+JSON.stringify({...baseline,checks:undefined}));
