/** Newly sourced third-party bare-KV holdout. Never prints source values. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {scoreKvFields,sourceKvReference} from '../../src/poc/syslogKvFieldFidelity';

type Oracle={sha256:string;file:string;fields:unknown};
type Counters={events:number;originalFields:number;candidateFields:number;
  exact:number;wrong:number;missing:number;extra:number;wholeEvents:number;
  parsed:number;rawRetained:number;contractMissing:number};
const make=():Counters=>({events:0,originalFields:0,candidateFields:0,
  exact:0,wrong:0,missing:0,extra:0,wholeEvents:0,
  parsed:0,rawRetained:0,contractMissing:0});
const root=path.join(os.homedir(),'.local/state/parserstudio-fresh-kv-20261017');
const files=[
  {file:'fg.log',bytes:647,sha:'e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2'},
  {file:'fg_long.log',bytes:171972,sha:'53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440'},
] as const;
const hash=(bytes:string|Buffer)=>crypto.createHash('sha256').update(bytes).digest('hex');
const oracle=JSON.parse(fs.readFileSync(path.join(root,'oracle-fresh-bare-kv-fields.json'),'utf8')) as Record<string,Oracle>;
if(Object.keys(oracle).length!==1002)throw Error('Fresh private oracle count drifted');
const seen=new Set<string>();
const byFile:Record<string,Counters>={
  'fg.log':make(),'fg_long.log':make(),
};
let originalLines=0,duplicateLines=0;
const modes:Record<string,number>={};
for(const entry of files){
  const blob=fs.readFileSync(path.join(root,entry.file));
  if(blob.length!==entry.bytes||hash(blob)!==entry.sha)throw Error('Pinned third-party fixture drifted');
  const lines=blob.toString('utf8').replace(/^\uFEFF/,'').split(/\r\n|\n|\r/).filter(x=>x.trim());
  for(const raw of lines){
    originalLines++;
    const id=hash(raw);
    if(seen.has(id)){duplicateLines++;continue;}
    seen.add(id);
    if(!Object.hasOwn(oracle,id)||oracle[id]!.sha256!==id||
       oracle[id]!.file!==entry.file)
      throw Error('Fresh independently qualified source identity mismatch');
    const source=sourceKvReference(oracle[id]!.fields);
    const output=parseSecurityInput(raw);
    const event=output.ok&&output.events.length===1?output.events[0]:undefined;
    const generic=event?.fields?.generic as Record<string,unknown>|undefined;
    // Pre-registered bare-KV contract; no post-hoc body/family fallback.
    const candidate=generic?.kv;
    const scored=scoreKvFields(source,candidate);
    const count=byFile[entry.file];
    count.events++;
    count.originalFields+=scored.expected;
    count.candidateFields+=scored.extracted;
    count.exact+=scored.exact;
    count.wrong+=scored.wrongValue;
    count.missing+=scored.missing;
    count.extra+=scored.unexpected;
    if(scored.exactEvent)count.wholeEvents++;
    if(output.ok)count.parsed++;
    if(output.ok&&output.source_raw===raw&&event?.raw===raw)count.rawRetained++;
    if(candidate===undefined||candidate===null)count.contractMissing++;
    const mode=typeof generic?.mode==='string'?generic.mode:'no_generic_mode';
    modes[mode]=(modes[mode]??0)+1;
  }
}
const values=Object.values(byFile);
const sum=(key:keyof Counters)=>values.reduce((a,b)=>a+b[key],0);
const original=sum('originalFields'),emitted=sum('candidateFields');
const tp=sum('exact'),wrong=sum('wrong'),missing=sum('missing'),extra=sum('extra');
const fp=wrong+extra,fn=wrong+missing;
if(originalLines!==1008||duplicateLines!==6||seen.size!==1002||
   original!==11848||tp+fn!==original||tp+fp!==emitted)
  throw Error('Fresh independent holdout denominator/accounting drifted');
const precision=emitted?tp/emitted:null;
const recall=tp/original;
const f1=precision===null?null:precision+recall?
  2*precision*recall/(precision+recall):0;
console.log('FRESH_BARE_KV_FIELD_FIDELITY '+JSON.stringify({
  pinnedThirdPartyRevision:'716cfcc3724a5765c5db21d8d76c7478cd2e7de9',
  physicallyPresentLines:originalLines,duplicateOriginalLinesExcluded:duplicateLines,
  independentlyScorableUniqueSources:seen.size,originalFields:original,
  candidateFields:emitted,truePositive:tp,falsePositive:fp,falseNegative:fn,
  wrongValueAtSourceName:wrong,missingSourceNames:missing,extraCandidateNames:extra,
  fullExactOriginalKvEvents:sum('wholeEvents'),
  parserAcceptedEvents:sum('parsed'),eventRawRetained:sum('rawRetained'),
  absentGenericKvContractTrees:sum('contractMissing'),
  precision,recall,f1,byFile,modes,
  evidenceClass:'FRESH_THIRD_PARTY_FIXTURE_NOT_PRODUCTION',
  semanticVerified:false,nativeVerified:false,automaticPromotion:false,
}));
