import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {scanPrefixedKeyValues} from '../../src/poc/losslessLexer';
import {inspectGrammarFunnel} from '../../src/poc/grammarFunnel';
import {assessPinnedSourceCandidate,pinnedTrustRegistrySummary} from '../../src/poc/sourceTrustRegistry';

type RecordInput={id:string;source:string;raw:string};
const root=path.join(os.homedir(),'.local/state/parserstudio-lossless-fresh-20261017');
const original=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as RecordInput[];
const oracle=JSON.parse(fs.readFileSync(path.join(root,'oracle-prefixed-development.json'),'utf8')) as
  Record<string,{prefix:string;fields:Array<[string,string]>}>;
const source=original.filter(row=>Object.prototype.hasOwnProperty.call(oracle,row.id));
if(source.length!==8||Object.keys(oracle).length!==8)
  throw Error('Expected eight private pinned original source fixtures');
let exact=0,negativeRejected=0,partial=0,notPromoted=0;
const bad:string[]=[];
for(const item of source){
  const diagnostic=inspectGrammarFunnel(item.raw);
  const candidate=scanPrefixedKeyValues(item.raw,0);
  if(!candidate||diagnostic.disposition!=='partial_candidate'){
    bad.push(item.id+':no_candidate');continue;
  }
  partial++;
  const result=await assessPinnedSourceCandidate(item.id,candidate);
  if(result.outcome==='PINNED_LEXICAL_MATCH_UNREVIEWED'&&
     result.oracleStage==='INDEPENDENT_LEXICAL_UNREVIEWED'&&
     result.sourceRawPreserved)exact++;
  else bad.push(item.id+':source_mismatch');
  if(!result.productPromotionAllowed&&!result.semanticMappingApproved&&
     !result.nativeRuntimeApproved)notPromoted++;
  const poisoned=scanPrefixedKeyValues(item.raw+' attacker_control=1',0);
  const rejected=poisoned?await assessPinnedSourceCandidate(item.id,poisoned):null;
  if(rejected===null||rejected.outcome!=='PINNED_LEXICAL_MATCH_UNREVIEWED')negativeRejected++;
  else bad.push(item.id+':altered_source_accepted');
}
const summary={pinnedCorpus:'70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039',
  registry:pinnedTrustRegistrySummary(),sources:source.length,
  independentlyPinnedExact:exact,partialCandidates:partial,
  negativeSourceMutationsRejected:negativeRejected,
  productPromotionsDenied:notPromoted,bad};
console.log('SOURCE_TRUST_REGISTRY_ORACLE '+JSON.stringify(summary));
if(source.length!==8||partial!==8||exact!==8||negativeRejected!==8||
  notPromoted!==8||bad.length)process.exitCode=1;
