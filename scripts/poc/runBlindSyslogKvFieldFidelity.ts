/** Private, aggregate-only scorer for the frozen non-JSON source KV oracle. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {scoreKvFields,sourceKvReference} from '../../src/poc/syslogKvFieldFidelity';

type Sample={id:string;source:string;raw:string};
type Oracle={sourceSha256:string;prefixHash:string;variant:'pri'|'yearless';
  family:string;fields:unknown};
type Counts={events:number;sourceFields:number;candidateFields:number;exact:number;
  wrongValue:number;missing:number;extra:number;nameSetExact:number;
  wholeEventExact:number;missingContractTree:number;eventRawPreserved:number};
const fixedSha='153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32';
const fixedRevision='ee918d03f4a90dacd32673546c64a633308796ef';
const root=path.join(os.homedir(),'.local/state/parserstudio-lossless-blind-20261017');
const read=(file:string):unknown=>JSON.parse(fs.readFileSync(path.join(root,file),'utf8'));
const digest=(text:string|Buffer)=>crypto.createHash('sha256').update(text).digest('hex');
const bytes=fs.readFileSync(path.join(root,'records.json'));
const sourceSha256=digest(bytes);
const manifest=read('manifest.json') as {revision:string;record_sha256:string;events:number};
const observation=read('final-observation.json') as {accepted:number;rawPreserved:number;total:number};
const records=JSON.parse(bytes.toString('utf8')) as Sample[];
const oracle=read('oracle-blind-syslog-kv-fields.json') as Record<string,Oracle>;

if(sourceSha256!==fixedSha||manifest.record_sha256!==fixedSha||
  manifest.revision!==fixedRevision||manifest.events!==222||
  observation.total!==222||observation.accepted!==217||observation.rawPreserved!==217||
  records.length!==222||Object.keys(oracle).length!==185)
  throw Error('Frozen independent source or field denominator changed');

const newCounts=():Counts=>({events:0,sourceFields:0,candidateFields:0,exact:0,
  wrongValue:0,missing:0,extra:0,nameSetExact:0,wholeEventExact:0,
  missingContractTree:0,eventRawPreserved:0});
const byFamily:Record<string,Counts>={
  sonicwall_firewall:newCounts(),fortinet_fortigate:newCounts(),
};
const seen=new Set<string>();
const mismatchClasses:Record<string,number>={};
let accepted=0,rawPreserved=0,eligible=0,eligibleParseFailed=0;
for(const row of records){
  if(typeof row.id!=='string'||typeof row.source!=='string'||typeof row.raw!=='string'||
     seen.has(row.id))throw Error('Duplicate or invalid frozen source record');
  seen.add(row.id);
  const output=parseSecurityInput(row.raw);
  if(output.ok){
    accepted++;
    if(output.source_raw===row.raw)rawPreserved++;
  }
  if(!Object.hasOwn(oracle,row.id))continue;
  eligible++;
  const proof=oracle[row.id]!;
  if(!Object.hasOwn(byFamily,proof.family)||proof.family!==row.source.split('/')[1]||
     digest(row.raw)!==proof.sourceSha256||
     !/^[a-f0-9]{64}$/.test(proof.prefixHash)||
     !['pri','yearless'].includes(proof.variant))
    throw Error('Independent KV source identity or envelope proof drifted');
  const reference=sourceKvReference(proof.fields);
  const family=byFamily[proof.family]!;
  if(!output.ok)eligibleParseFailed++;
  const event=output.ok&&output.events.length===1?output.events[0]:undefined;
  const fields=event?.fields;
  const vendor=fields?.fortinet as Record<string,unknown>|undefined;
  const generic=fields?.generic as Record<string,unknown>|undefined;
  // These are the existing parser contracts; no body inference or field renaming.
  const candidate=proof.family==='fortinet_fortigate'?vendor?.fields:generic?.kv;
  const scored=scoreKvFields(reference,candidate);
  if(scored.wrongValue){
    const actual=candidate!==null&&typeof candidate==='object'&&!Array.isArray(candidate)
      ?candidate as Record<string,unknown>:{};
    for(const [name,value] of reference){
      if(!Object.hasOwn(actual,name)||actual[name]===value)continue;
      const found=actual[name];
      const cause=typeof found!=='string'?'type_drift':
        found===value.trim()?'trim_drift':
        found===value.replace(/\\(.)/gs,'$1')?'oracle_keeps_escape':
        value===found.replace(/\\(.)/gs,'$1')?'parser_keeps_escape':
        found.length>value.length?'candidate_longer':
        found.length<value.length?'candidate_shorter':'equal_length_difference';
      const fingerprint=cause+(value.includes('\\')?'_oracle_has_backslash':'_no_backslash');
      mismatchClasses[fingerprint]=(mismatchClasses[fingerprint]??0)+1;
    }
  }
  family.events++;
  family.sourceFields+=scored.expected;
  family.candidateFields+=scored.extracted;
  family.exact+=scored.exact;
  family.wrongValue+=scored.wrongValue;
  family.missing+=scored.missing;
  family.extra+=scored.unexpected;
  if(scored.exactNameSet)family.nameSetExact++;
  if(scored.exactEvent)family.wholeEventExact++;
  if(candidate===undefined||candidate===null)family.missingContractTree++;
  if(output.ok&&output.source_raw===row.raw&&event?.raw===row.raw)
    family.eventRawPreserved++;
}
const sw=byFamily.sonicwall_firewall,ft=byFamily.fortinet_fortigate;
if(seen.size!==222||eligible!==185||accepted!==217||rawPreserved!==217||
   sw.events!==178||sw.sourceFields!==3869||ft.events!==7||ft.sourceFields!==291)
  throw Error('Frozen source/Oracle totals or unchanged parser baseline drifted');

const sum=(property:keyof Counts)=>sw[property]+ft[property];
const expected=sum('sourceFields'),candidate=sum('candidateFields');
const truePositive=sum('exact'),wrongValue=sum('wrongValue');
const missing=sum('missing'),extra=sum('extra');
const falsePositive=wrongValue+extra,falseNegative=wrongValue+missing;
if(expected!==4160||truePositive+falseNegative!==expected||
   truePositive+falsePositive!==candidate)
  throw Error('Non-JSON independent source KV accounting invalid');
const precision=candidate?truePositive/candidate:null;
const recall=truePositive/expected;
const f1=precision===null?null:precision+recall?2*precision*recall/(precision+recall):0;
console.log('BLIND_SYSLOG_KV_FIELD_FIDELITY '+JSON.stringify({
  sourceSha256,corpusEvents:222,baselineStructuralAccepted:accepted,
  baselineSourceRawPreserved:rawPreserved,eligibleNonJsonRecords:eligible,
  independentlyQualifiedSourceKvFields:expected,unscoredOtherRecords:222-eligible,
  eligibleParserFailures:eligibleParseFailed,parserKvCandidates:candidate,
  truePositiveExactNameAndValue:truePositive,falsePositive,falseNegative,
  wrongValueAtOriginalName:wrongValue,mismatchClasses,missingOriginalNames:missing,
  unexpectedNames:extra,nameSetsExact:sum('nameSetExact'),
  fullKvEventsExact:sum('wholeEventExact'),
  absentExpectedContractTrees:sum('missingContractTree'),
  eligibleEventRawPreserved:sum('eventRawPreserved'),
  precisionDenominator:candidate,recallDenominator:expected,
  exactFieldPrecision:precision,exactFieldRecall:recall,exactFieldF1:f1,
  evidenceClass:'POST_HOC_IN_FAMILY',semanticMapping:'NOT_SCORED',
  nativeExecution:'NOT_VERIFIED',unsupportedProse:'UNSCORED',
  byFamily,
}));
