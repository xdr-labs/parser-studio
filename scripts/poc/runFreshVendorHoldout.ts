import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {parseSyslogEnvelope} from '../../src/syslogEnvelope';

type Sample={id:string;source:string;raw:string};
const root=process.env.PARSER_STUDIO_FRESH_HOLDOUT_DIR ??
  path.join(os.homedir(),'.local/state/parserstudio-fresh-vendor-holdout-20261016');
const events=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as Sample[];
const knownInvalid=JSON.parse(fs.readFileSync(path.join(root,'known_invalid.json'),'utf8')) as Sample[];
const familyStats:Record<string,{events:number;parsed:number;failedIds:string[]}>={};

function sourceScalars(input:unknown):string[]{
  if(input===null||input===undefined)return [];
  if(Array.isArray(input))return input.flatMap(sourceScalars);
  if(typeof input==='object')return Object.entries(input as Record<string,unknown>)
    .flatMap(([key,value])=>/^(source_raw|raw|message_raw|raw_lines|source_index)$/i.test(key)?[]:sourceScalars(value));
  return [String(input)];
}

let accepted=0,jsonEvents=0,expectedScalars=0,recoveredScalars=0,jsonFailed=0;
let jsonMalformedAccepted=0,knownInvalidAccepted=0;
let residualEnvelopeRecognized=0,residualEnvelopeUnknown=0,residualWithThreeKvPairs=0;
for(const sample of events){
  const family=sample.source.split('/').slice(0,2).join('/');
  const group=familyStats[family]??={events:0,parsed:0,failedIds:[]};
  group.events++;
  const result=parseSecurityInput(sample.raw);
  if(result.ok){accepted++;group.parsed++;}
  else {
    if(group.failedIds.length<8)group.failedIds.push(sample.id);
    const envelope=parseSyslogEnvelope(sample.raw);
    if(envelope)residualEnvelopeRecognized++;
    else residualEnvelopeUnknown++;
    const body=envelope?.message??sample.raw;
    const kvPairs=(body.match(/(?:^|[ \t])[A-Za-z_][A-Za-z0-9_-]{1,64}=/g)??[]).length;
    if(kvPairs>=3)residualWithThreeKvPairs++;
  }

  if(family==='crowdstrike/falcon'){
    const original=JSON.parse(sample.raw);
    jsonEvents++;
    const expected=sourceScalars(original);
    const extracted=sourceScalars(result.ok?result.events.map(event=>event.fields):[]);
    expectedScalars+=expected.length;
    let complete=true;
    for(const scalar of expected){
      const index=extracted.indexOf(scalar);
      if(index<0)complete=false;
      else{recoveredScalars++;extracted.splice(index,1);}
    }
    if(!complete)jsonFailed++;
    const truncated=sample.raw.slice(0,-1);
    const unsafe=sample.raw.replace('{','{"__proto__":{"forbidden":true},');
    if(parseSecurityInput(truncated).ok)jsonMalformedAccepted++;
    if(parseSecurityInput(unsafe).ok)jsonMalformedAccepted++;
  }
}
for(const sample of knownInvalid){
  if(parseSecurityInput(sample.raw).ok)knownInvalidAccepted++;
}
const summary={
  record_sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'records.json'))).digest('hex'),
  events:events.length,accepted,failures:events.length-accepted,
  residualEnvelopeRecognized,residualEnvelopeUnknown,residualWithThreeKvPairs,
  jsonEvents,expectedScalars,recoveredScalars,jsonFailed,
  malformedJsonTests:jsonEvents*2,malformedJsonAccepted:jsonMalformedAccepted,
  knownInvalidControls:knownInvalid.length,knownInvalidAccepted,
  groups:familyStats,
};
console.log('FRESH_VENDOR_HOLDOUT_QUALIFICATION '+JSON.stringify(summary));
const good=events.length===571&&accepted===535&&
  familyStats['juniper_srx/log']?.events===105&&familyStats['juniper_srx/log']?.parsed===86&&
  familyStats['checkpoint/firewall']?.events===111&&familyStats['checkpoint/firewall']?.parsed===109&&
  familyStats['sophos/xg']?.events===271&&familyStats['sophos/xg']?.parsed===256&&
  familyStats['crowdstrike/falcon']?.events===84&&familyStats['crowdstrike/falcon']?.parsed===84&&
  jsonEvents===84&&expectedScalars===3092&&recoveredScalars===3092&&jsonFailed===0&&
  jsonMalformedAccepted===0&&knownInvalid.length===1&&knownInvalidAccepted===0&&
  residualEnvelopeRecognized===23&&residualEnvelopeUnknown===13&&residualWithThreeKvPairs===23;
if(!good){process.exitCode=1;console.error('Fresh vendor holdout did not meet recorded qualification');}
