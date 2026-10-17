import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {inspectGrammarFunnel} from '../../src/poc/grammarFunnel';
import {scanKeyValues,scanPrefixedKeyValues} from '../../src/poc/losslessLexer';

type Sample={id:string;source:string;raw:string};
type Prior={id:string;ok:boolean;kind:string|null;count:number;rawRetained:boolean};
type Oracle=Record<string,Record<string,Record<string,string>>>;
const root=process.env.PARSER_STUDIO_LOSSLESS_DIR ??
  path.join(os.homedir(),'.local/state/parserstudio-lossless-fresh-20261017');
const mode=process.argv.includes('--evaluation')?'evaluation':'development';
const baselineCountKey=mode==='evaluation'?'eval_baseline_parsed':'dev_baseline_parsed';
const split=JSON.parse(fs.readFileSync(path.join(root,'split.json'),'utf8'));
const raw=fs.readFileSync(path.join(root,'records.json'));
const sourceSha=crypto.createHash('sha256').update(raw).digest('hex');
const previous=JSON.parse(fs.readFileSync(path.join(root,'baseline.json'),'utf8')) as {
  base_sha:string;records_sha256:string;checks:Prior[];
};
if(previous.base_sha!=='6b4f125d01e8d90a9306ba64b1a2c46b1f84c863'||
   previous.records_sha256!==sourceSha||split.events_sha256!==sourceSha)
  throw Error('Pinned independent data or baseline identity drifted');
const expected=mode==='development'?
  {events:124,baseline:112,sourceOracle:61,prefixOracle:8}:
  {events:141,baseline:117,sourceOracle:76,prefixOracle:0};
const files=new Set<string>(split[mode+'_files']);
const records=(JSON.parse(raw.toString('utf8')) as Sample[]).filter(row=>files.has(row.source));
if(records.length!==split[mode+'_events'])throw Error('Frozen split cardinality drift');
const priorById=new Map(previous.checks.map(row=>[row.id,row]));
const oracleFile=path.join(root,'oracle-'+mode+'.json');
const prefixFile=path.join(root,'oracle-prefixed-'+mode+'.json');
if(!fs.existsSync(oracleFile)||!fs.existsSync(prefixFile))
  throw Error('Independent source-field oracle is missing for '+mode);
const oracle=JSON.parse(fs.readFileSync(oracleFile,'utf8')) as Oracle;
const prefixedOracle=JSON.parse(fs.readFileSync(prefixFile,'utf8')) as
  Record<string,{prefix:string;fields:Array<[string,string]>}>;
if(Object.keys(oracle).length!==expected.sourceOracle||
   Object.keys(prefixedOracle).length!==expected.prefixOracle||
   records.length!==expected.events||split[baselineCountKey]!==expected.baseline)
  throw Error('Pinned nonempty source oracle or evaluation denominator drift');
const groups:Record<string,{events:number;baseline:number;suggestions:number;ambiguous:number;rawOnly:number;partial:number}>={};
let parsed=0,baselineDrift=0,sourceSuggestions=0,positionalSuggestions=0,partialSuggestions=0;
let ambiguous=0,noCandidate=0,sourceExact=0,sourceMismatch=0,oracleCandidateRows=0;
let recheck=0,prefixedExact=0,prefixedMismatch=0;
const mismatchIds:string[]=[];
const examples:string[]=[];
for(const row of records){
  const prior=priorById.get(row.id);
  if(!prior)throw Error('Unknown frozen source record ID: '+row.id);
  const original=parseSecurityInput(row.raw);
  const ok=original.ok;
  if(ok)parsed++;
  if(ok!==prior.ok||(ok&&original.kind!==prior.kind)||
     (ok&&original.events.length!==prior.count)||
     (ok&&original.source_raw!==row.raw)||(!ok&&prior.rawRetained))baselineDrift++;
  const measured=inspectGrammarFunnel(row.raw,ok);
  const family=row.source.split('/')[1]!;
  const group=groups[family]??={events:0,baseline:0,suggestions:0,ambiguous:0,rawOnly:0,partial:0};
  group.events++;
  if(ok)group.baseline++;
  if(measured.disposition==='candidate_only'){
    group.suggestions++;
    if(measured.selected?.naming==='source')sourceSuggestions++;
    else positionalSuggestions++;
    if(examples.length<9)examples.push(row.id+':'+measured.selected?.grammar);
  }
  if(measured.disposition==='partial_candidate'){
    group.partial++;
    partialSuggestions++;
    if(examples.length<9)examples.push(row.id+':'+measured.selected?.grammar);
  }
  if(measured.disposition==='ambiguous'){ambiguous++;group.ambiguous++;}
  if(measured.disposition==='raw_only'||measured.disposition==='invalid_envelope'){
    group.rawOnly++;if(!ok)noCandidate++;
  }
  for(const candidate of measured.candidates){
    if(candidate.tokenSpansReplayed&&candidate.fullBodyCovered)recheck++;
  }
  const prefixedExpected=prefixedOracle[row.id];
  if(prefixedExpected){
    const lexical=measured.bodyStart!==null?
      scanPrefixedKeyValues(row.raw,measured.bodyStart):null;
    if(lexical&&
       row.raw.slice(lexical.prefixSpan!.start,lexical.prefixSpan!.end)===prefixedExpected.prefix&&
       lexical.fields.length===prefixedExpected.fields.length&&
       lexical.fields.every((field,index)=>{
         const pair=prefixedExpected.fields[index];
         return pair!==undefined&&pair[0]===field.key&&pair[1]===field.value;
       }))prefixedExact++;
    else {
      prefixedMismatch++;
      mismatchIds.push(row.id+':prefixed-independent-oracle');
    }
  }
  const expected=oracle[row.id];
  if(expected){
    oracleCandidateRows++;
    for(const c of measured.candidates){
      const oracleName=c.grammar==='prefixed_kv_space'?c.grammar:c.grammar.replace(/^kv_/,'');
      const exact=expected[oracleName];
      if(!exact||c.naming!=='source')continue;
      // This comparison requires that the candidate was replayed, and uses
      // independently decoded Python source fields, not an inferred mapping.
      const chosen=c.grammar==='prefixed_kv_space'?
        scanPrefixedKeyValues(row.raw,measured.bodyStart!):
        scanKeyValues(row.raw,measured.bodyStart!,c.grammar.slice(3) as
          'space'|'pipe'|'semicolon'|'tab'|'comma',{preserveRepeated:true});
      if(chosen&&Object.keys(exact).length===chosen.fields.length&&
         chosen.fields.every(f=>exact[f.key]===f.value))sourceExact++;
      else {sourceMismatch++;mismatchIds.push(row.id+':'+c.grammar);}
    }
  }
}
const summary={mode,sourceSha,events:records.length,baselineParsed:parsed,
  baselineExpected:split[baselineCountKey],baselineDrift,
  recoveredAutomatically:0, // no promotion without independently approved source grammar
  reviewCandidates:sourceSuggestions+positionalSuggestions+partialSuggestions,partialSuggestions,sourceSuggestions,
  positionalSuggestions,ambiguous,unresolvedWithoutCandidates:noCandidate,
  lexicalReplayCount:recheck,independentOracleRecords:oracleCandidateRows,
  independentPrefixedOracleRecords:Object.keys(prefixedOracle).length,
  exactPrefixedOracleEvents:prefixedExact,incorrectPrefixedOracleEvents:prefixedMismatch,
  matchedOracleCandidates:sourceExact,oracleValueMismatch:sourceMismatch,
  mismatchIds,examples,groups};
console.log('LOSSLESS_GRAMMAR_POC '+JSON.stringify(summary));
if(parsed!==split[baselineCountKey]||baselineDrift||sourceMismatch||prefixedMismatch||
  oracleCandidateRows!==expected.sourceOracle||sourceExact!==expected.sourceOracle||
  prefixedExact!==expected.prefixOracle)
  process.exitCode=1;
