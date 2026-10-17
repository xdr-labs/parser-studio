/** Third-party original RFC3164 KV holdout; output only aggregate metrics. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {scoreKvFields,sourceKvReference} from '../../src/poc/syslogKvFieldFidelity';

type Expected={sha256:string;variant:string;fields:unknown;prefixHash:string};
type Oracle={revision:string;sourceFileHash:string;accepted:Record<string,Expected>;
  unscorableSourceSha256:string[]};
const root=path.join(os.homedir(),'.local/state/parserstudio-fresh-sonicwall-20261017');
const pin='bc8c137fe913ba43a4345850206565b028e8fef8';
const sourceSha='949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9';
const hash=(value:string|Buffer)=>crypto.createHash('sha256').update(value).digest('hex');
const original=fs.readFileSync(path.join(root,'sonicwall.log.orig'));
const oracle=JSON.parse(fs.readFileSync(path.join(root,'oracle-fresh-sonicwall-syslog-kv.json'),'utf8')) as Oracle;
if(original.length!==13709||hash(original)!==sourceSha||
   oracle.sourceFileHash!==sourceSha||oracle.revision!==pin||
   Object.keys(oracle.accepted).length!==59||oracle.unscorableSourceSha256.length!==2)
  throw Error('Fresh original SonicWall or Oracle pin drifted');
const lines=original.toString('utf8').replace(/^\uFEFF/,'')
  .split(/\r\n|\n|\r/).filter(x=>x.trim());
if(lines.length!==61||new Set(lines).size!==61)
  throw Error('Fresh SonicWall original record count drifted');
const excluded=new Set(oracle.unscorableSourceSha256);
const accepted=new Set(Object.keys(oracle.accepted));
if([...excluded].some(id=>accepted.has(id)))
  throw Error('A source cannot be both independently qualified and unscoreable');
let sourceFields=0,candidateFields=0,exact=0,wrong=0,missing=0,extra=0;
let exactEvents=0,qualifiedParserAccepts=0,qualifiedRawPreserved=0;
let unscoreableCount=0,unscorableParserAccepts=0;
let contractTreeAbsent=0;
const modes:Record<string,number>={};
const seen=new Set<string>();
for(const raw of lines){
  const sha=hash(raw);
  if(seen.has(sha))throw Error('Fresh original source duplicate');
  seen.add(sha);
  const output=parseSecurityInput(raw);
  if(excluded.has(sha)){
    unscoreableCount++;
    if(output.ok)unscorableParserAccepts++;
    continue; // Never infer missing original KV ground truth.
  }
  if(!accepted.has(sha)||oracle.accepted[sha]!.sha256!==sha||
     oracle.accepted[sha]!.variant!=='yearless')
    throw Error('Fresh independent SonicWall source identity mismatch');
  const reference=sourceKvReference(oracle.accepted[sha]!.fields);
  const event=output.ok&&output.events.length===1?output.events[0]:undefined;
  const generic=event?.fields?.generic as Record<string,unknown>|undefined;
  const candidates=generic?.kv;
  const measured=scoreKvFields(reference,candidates);
  sourceFields+=measured.expected;
  candidateFields+=measured.extracted;
  exact+=measured.exact;wrong+=measured.wrongValue;
  missing+=measured.missing;extra+=measured.unexpected;
  if(measured.exactEvent)exactEvents++;
  if(output.ok)qualifiedParserAccepts++;
  if(output.ok&&output.source_raw===raw&&event?.raw===raw)qualifiedRawPreserved++;
  if(candidates===undefined||candidates===null)contractTreeAbsent++;
  const mode=typeof generic?.mode==='string'?generic.mode:'no_generic_mode';
  modes[mode]=(modes[mode]??0)+1;
}
const tp=exact,fp=wrong+extra,fn=wrong+missing;
if(seen.size!==61||unscoreableCount!==2||sourceFields!==759||
   tp+fn!==sourceFields||tp+fp!==candidateFields)
  throw Error('Fresh independent SonicWall field denominator/accounting invalid');
const p=candidateFields?tp/candidateFields:null;
const r=tp/sourceFields;
console.log('FRESH_SONICWALL_SYSLOG_KV_FIELD_FIDELITY '+JSON.stringify({
  pinnedSourceRevision:pin,sourceFileSha256:sourceSha,sourceRawRecords:61,
  independentlyQualifiedRecords:59,independentSourceKvFields:sourceFields,
  rejectedUnscorableRecords:unscoreableCount,
  productAcceptedButUnscorable:unscorableParserAccepts,
  productAcceptedQualifiedRecords:qualifiedParserAccepts,
  productKvCandidates:candidateFields,truePositive:tp,falsePositive:fp,
  falseNegative:fn,wrongSourceValues:wrong,missingSourceNames:missing,
  unexpectedProductNames:extra,fullSourceKvEventsExact:exactEvents,
  productRecordRawsPreserved:qualifiedRawPreserved,
  missingFixedProductKvTrees:contractTreeAbsent,parserModes:modes,
  nameValuePrecision:p,nameValueRecall:r,
  nameValueF1:p===null?null:p+r?2*p*r/(p+r):0,
  evidenceClass:'THIRD_PARTY_ORIGINAL_RFC3164_LEXICAL_ONLY',
  qualifiedManufacturerSemantics:false,nativeOrDpQualified:false,
  unscorableEventsClaimedExact:false,
}));
