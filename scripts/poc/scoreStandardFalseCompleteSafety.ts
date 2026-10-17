/** Score the unchanged browser baseline and separate fail-closed source PoC
 * against a frozen, standards-derived synthetic diagnostic set.
 * Do not present this as a shipped product fix or open-world field F1.
 */
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {extractFields} from '../../src/parser';
import {inspectSourceCompleteness} from '../../src/poc/standardSourceCompletenessGate';
import type {ConcreteFormat,ParserDraft} from '../../src/model';

const EXPECTED_CASE_SHA='c89685936c1a2b38840695d3de0338c824d6ba57e8e9a135214c9569d7534b1d';
const file=path.join(path.dirname(fileURLToPath(import.meta.url)),'standardGrammarCases.v1.json');
const bytes=fs.readFileSync(file);
if(createHash('sha256').update(bytes).digest('hex')!==EXPECTED_CASE_SHA)
  throw Error('P0-STD pre-candidate normative-derived case set drifted');
type Case={id:string;family:string;raw:string;requireReview?:string};
const cases=(JSON.parse(bytes.toString('utf8')) as {cases:Case[]}).cases;
let eligible=0,priorSilent=0,nowSafe=0,dispositionUnknown=0,byteDrift=0,
 independentDeviceTruth=0,sourceSemanticPromotions=0;
for(const row of cases){
 if(!row.requireReview||!['json','kv'].includes(row.family))continue;
 eligible++;
 const old=extractFields(row.raw,row.family as ConcreteFormat,{} as ParserDraft);
 priorSilent+=Number(old.errors.length===0);
 const inspected=inspectSourceCompleteness(row.raw,row.family as 'json'|'kv');
 nowSafe+=Number(inspected.disposition==='REVIEW_ONLY_UNCERTAIN'&&
   inspected.issues.includes(row.requireReview as typeof inspected.issues[number])&&
   inspected.namedRawFields.length===0&&!inspected.completeSourceClaim);
 byteDrift+=Number(inspected.raw!==row.raw||
  inspected.sourceBytes!==new TextEncoder().encode(row.raw).length);
 dispositionUnknown+=Number(inspected.disposition==='REVIEW_ONLY_LEXICAL');
 sourceSemanticPromotions+=Number(inspected.autoPromoted||
   inspected.nativeStellar!=='NOT_VERIFIED');
}
console.log('P0_STD_FALSE_COMPLETE_SOURCE_GATE '+JSON.stringify({
 referenceCaseSha:EXPECTED_CASE_SHA,syntheticStandardsDerivedNotExternalOracle:true,
 totalFrozenCases:cases.length,eligible,baselineBrowserSilentSuccess:priorSilent,
 newSourceGateReviewOrAbstain:nowSafe,stillUnknown:dispositionUnknown,
 sourceByteDrift:byteDrift,sourceOrNativePromotions:sourceSemanticPromotions,
 independentDeviceTruth,wholeEventFP:'UNSCORABLE',
 productImplementationChanged:false,fullSourceAccuracyCertified:false,
 }));
if(eligible!==5||priorSilent!==5||nowSafe!==5||byteDrift||dispositionUnknown||
 sourceSemanticPromotions)process.exitCode=1;
