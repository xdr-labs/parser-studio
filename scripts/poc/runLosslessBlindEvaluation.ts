import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {inspectGrammarFunnel} from '../../src/poc/grammarFunnel';
import {scanKeyValues,scanPrefixedKeyValues} from '../../src/poc/losslessLexer';

type Sample={id:string;source:string;raw:string};
type Oracle=Record<string,Record<string,Record<string,string>>>;
type PrefixOracle=Record<string,{prefix:string;fields:Array<[string,string]>}>;

const root=path.join(os.homedir(),'.local/state/parserstudio-lossless-blind-20261017');
const read=(name:string)=>JSON.parse(fs.readFileSync(path.join(root,name),'utf8'));
const raw=fs.readFileSync(path.join(root,'records.json'));
const rows=JSON.parse(raw.toString('utf8')) as Sample[];
const manifest=read('manifest.json');
const flat=read('oracle-flat.json') as Oracle;
const prefixed=read('oracle-prefix.json') as PrefixOracle;
const independentSummary=read('oracle-summary.json');
const sha=crypto.createHash('sha256').update(raw).digest('hex');
if(manifest.revision!=='ee918d03f4a90dacd32673546c64a633308796ef'||
   sha!=='153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32'||
   manifest.record_sha256!==sha||manifest.events!==222||manifest.files.length!==9||
   rows.length!==222||Object.keys(flat).length!==independentSummary.flat_events||
   Object.keys(prefixed).length!==independentSummary.prefix_events)
  throw Error('Unseen source corpus or independent oracle is missing or changed');

let accepted=0,rawPreserved=0,newReview=0,partial=0,anonymous=0,
  unmatched=0,matchedFlat=0,comparedFlat=0,matchedPrefix=0,comparedPrefix=0;
const sampleErrors:string[]=[];
const groups:Record<string,{total:number;accepted:number;review:number;unmatched:number}>={};
for(const row of rows){
  const vendor=row.source.split('/')[1]!;
  const group=groups[vendor]??={total:0,accepted:0,review:0,unmatched:0};
  group.total++;
  const result=parseSecurityInput(row.raw);
  if(result.ok){
    accepted++;group.accepted++;
    if(result.source_raw===row.raw)rawPreserved++;
    else sampleErrors.push(row.id+':raw-drift');
  }
  const inspected=inspectGrammarFunnel(row.raw,result.ok);
  if(inspected.selected){
    if(result.ok)sampleErrors.push(row.id+':baseline-overridden');
    else{
      newReview++;group.review++;
      if(inspected.disposition==='partial_candidate')partial++;
      if(inspected.selected.naming==='positional')anonymous++;
    }
  }else if(!result.ok){unmatched++;group.unmatched++;}
  const ref=flat[row.id];
  if(ref){
    const bodyStart=inspected.bodyStart;
    if(bodyStart!==null){
      for(const [separator,expected] of Object.entries(ref)){
        const found=scanKeyValues(row.raw,bodyStart,separator as
          'space'|'pipe'|'semicolon'|'tab'|'comma',{preserveRepeated:true});
        if(!found)continue;
        comparedFlat++;
        const accurate=Object.keys(expected).length===found.fields.length&&
          found.fields.every(f=>expected[f.key]===f.value);
        if(accurate)matchedFlat++;
        else sampleErrors.push(row.id+':flat-value-mismatch');
      }
    }
  }
  const pref= prefixed[row.id];
  if(pref){
    const candidate=inspected.bodyStart!==null?
      scanPrefixedKeyValues(row.raw,inspected.bodyStart):null;
    if(candidate){
      comparedPrefix++;
      const sourcePrefix=row.raw.slice(candidate.prefixSpan!.start,candidate.prefixSpan!.end);
      const correct=sourcePrefix===pref.prefix&&
        candidate.fields.length===pref.fields.length&&
        candidate.fields.every((f,index)=>f.key===pref.fields[index]?.[0]&&
          f.value===pref.fields[index]?.[1]);
      if(correct)matchedPrefix++;
      else sampleErrors.push(row.id+':prefix-value-mismatch');
    }
  }
}
const summary={sourceSha:sha,total:rows.length,accepted,rawPreserved,
  reviewCandidates:newReview,partial,anonymous,unmatched,
  sourceOracleEvents:Object.keys(flat).length,
  sourceFieldOracleGate:(Object.keys(flat).length+Object.keys(prefixed).length)>0?
    'SOURCE_VALUES_COMPARED':'NOT_SCORABLE_NO_SOURCE_FIELD_ORACLE',
  comparedFlat,matchedFlat,
  prefixOracleEvents:Object.keys(prefixed).length,
  comparedPrefix,matchedPrefix,
  errors:sampleErrors.slice(0,12),groups,
  automaticallyPromoted:0};
console.log('LOSSLESS_BLIND_EVALUATION '+JSON.stringify(summary));
const output=path.join(root,'final-observation.json');
const serialized=JSON.stringify(summary);
if(fs.existsSync(output)){
  if(fs.readFileSync(output,'utf8')!==serialized)
    throw Error('Blind evaluation changed from its original recorded observation');
}else{fs.writeFileSync(output,serialized,{mode:0o600});}
if(sampleErrors.length||rawPreserved!==accepted||
  (Object.keys(flat).length>0&&comparedFlat===0)||
  (Object.keys(prefixed).length>0&&comparedPrefix===0)||
  matchedFlat!==comparedFlat||matchedPrefix!==comparedPrefix)
  process.exitCode=1;
