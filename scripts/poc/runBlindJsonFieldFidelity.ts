import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {parseSecurityInput} from '../../src/securityInputPipeline';
import {compareJsonValues,jsonLeaves,type Leaf} from '../../src/poc/jsonFieldFidelity';

type Sample={id:string;source:string;raw:string};
type SourceOracle={sourceSha256:string;family:string;fields:Record<string,Leaf>};
type Family={documents:number;exactDocuments:number;sourceFields:number;extractedFields:number;
  exactValues:number;incorrectValues:number;missingPaths:number;unexpectedPaths:number};
const root=path.join(os.homedir(),'.local/state/parserstudio-lossless-blind-20261017');
const read=(file:string)=>JSON.parse(fs.readFileSync(path.join(root,file),'utf8'));
const originalBytes=fs.readFileSync(path.join(root,'records.json'));
const sha=crypto.createHash('sha256').update(originalBytes).digest('hex');
const manifest=read('manifest.json') as {revision:string;record_sha256:string;events:number};
const observations=read('final-observation.json') as {accepted:number;rawPreserved:number;total:number};
const records=JSON.parse(originalBytes.toString('utf8')) as Sample[];
const oracle=read('oracle-blind-json-fields.json') as Record<string,SourceOracle>;
if(sha!=='153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32'||
   manifest.record_sha256!==sha||manifest.events!==222||
   manifest.revision!=='ee918d03f4a90dacd32673546c64a633308796ef'||
   observations.total!==222||observations.accepted!==217||
   observations.rawPreserved!==217||records.length!==222||
   Object.keys(oracle).length!==22)
  throw Error('Independent blind source corpus or original scored denominator drifted');
let expected=0,extracted=0,exact=0,mismatched=0,missing=0,unexpected=0,
    sourceExact=0,processed=0,baselineParsed=0,baselineRawPreserved=0;
const byFamily:Record<string,Family>={};
for(const row of records){
 const output=parseSecurityInput(row.raw);
 if(output.ok){baselineParsed++;if(output.source_raw===row.raw)baselineRawPreserved++;}
 const reference=oracle[row.id];
 if(!reference)continue;  // Non-JSON records have no independent field oracle.
 processed++;
 if(crypto.createHash('sha256').update(row.raw).digest('hex')!==reference.sourceSha256||
    reference.family!==row.source.split('/')[1])
   throw Error('Independent per-original fixture source identity mismatch');
 const source=JSON.parse(row.raw) as Record<string,unknown>;
 const check=jsonLeaves(source);
 const expectedPaths=Object.entries(reference.fields);
 if(expectedPaths.length!==check.size||
    !expectedPaths.every(([key,value])=>check.has(key)&&check.get(key)===value))
   throw Error('Independent Python and JS source pointers disagree');
 const projected=output.ok&&output.events.length===1?output.events[0]?.fields:null;
 const score=compareJsonValues(new Map(expectedPaths),projected,source);
 if(score.exactStructure&&score.exactValues===score.expected)sourceExact++;
 expected+=score.expected;extracted+=score.extracted;exact+=score.exactValues;
 mismatched+=score.mismatchedValues;missing+=score.missingPaths;unexpected+=score.unexpectedPaths;
 const family=byFamily[reference.family]??={documents:0,exactDocuments:0,
   sourceFields:0,extractedFields:0,exactValues:0,incorrectValues:0,
   missingPaths:0,unexpectedPaths:0};
 family.documents++;if(score.exactStructure&&score.exactValues===score.expected)family.exactDocuments++;
 family.sourceFields+=score.expected;family.extractedFields+=score.extracted;
 family.exactValues+=score.exactValues;family.incorrectValues+=score.mismatchedValues;
 family.missingPaths+=score.missingPaths;family.unexpectedPaths+=score.unexpectedPaths;
}
if(processed!==22||expected!==882||baselineParsed!==217||baselineRawPreserved!==217)
 throw Error('JSON scored originals or baseline structurally parsed records changed');
const output={
 sourceSha256:sha,sourceEvents:222,baselineStructural:baselineParsed,
 baselineRawPreserved,fieldOracleEligibleDocuments:processed,
 fieldOracleEligibleSources:expected,scoredOriginalLeaves:expected,
 extractedLeaves:extracted,exactPathAndValueMatches:exact,
 wrongValueAtOriginalPath:mismatched,missingSourcePaths:missing,
 additionalUnexpectedPaths:unexpected,fullOriginalJsonDocumentsExact:sourceExact,
 precisionDenominator:extracted,recallDenominator:expected,
 fieldValuePrecision:extracted?exact/extracted:null,
 fieldValueRecall:expected?exact/expected:null,
 semanticMappingScore:'NOT_SCORED',nativeParserCompatibility:'NOT_VERIFIED',
 unsupportedNonJsonFieldScore:'NOT_SCORED_WITHOUT_ORACLE',
 targetApproved:0,sourceFamilyCounts:byFamily,
};
console.log('BLIND_JSON_FIELD_FIDELITY '+JSON.stringify(output));
if(exact+missing+mismatched!==expected||
   exact+mismatched+unexpected!==extracted)
 process.exitCode=1;
