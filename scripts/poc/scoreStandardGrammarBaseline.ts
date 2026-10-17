/** Normative-derived structural smoke baseline against unchanged implementation.
 * Authored examples are NOT blind external event/firmware correctness goldens.
 * Captures gaps, intentional fail-closed behavior and browser-vs-source divergence.
 */
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {extractFields} from '../../src/parser';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
import {arbitrateIndependentLeef} from '../../src/poc/independentLeefSource';
import {inspectGeneralSyslogEnvelope} from '../../src/poc/generalSyslogEnvelopeSpans';
import type {ParserDraft,ConcreteFormat} from '../../src/model';
const filename=path.join(path.dirname(fileURLToPath(import.meta.url)),'standardGrammarCases.v1.json');
const bytes=fs.readFileSync(filename);
const digest=createHash('sha256').update(bytes).digest('hex');
type Case={id:string;family:'cef'|'leef'|'json'|'kv'|'csv'|'syslog5424';
 spec:string;raw:string;csvColumns?:string;mustHave?:Record<string,string|number>;
 requireReview?:string};
const suite=JSON.parse(bytes.toString('utf8')) as {contract:string;scope:string;cases:Case[]};
if(suite.contract!=='parserstudio.standards-grammar-audit.v0.1'||suite.cases.length<20)
 throw Error('Unpinned standard-derived conformance fixture contract changed');
const rows:Array<{id:string;family:string;reference:string;verdict:string;
  sourceObserver:string;errorCount:number;completeClaim:boolean;reason:string}>=[];
let exact=0,missing=0,unsafe=0,review=0,sourceReview=0,sourceAbstain=0;
for(const item of suite.cases){
 let errors:string[]=[];
 let fields:Record<string,unknown>={};
 if(item.family==='syslog5424'){
  const output=inspectGeneralSyslogEnvelope(item.raw);
  fields=Object.fromEntries(output.fields.map(x=>[x.name,x.value]));
  errors=output.disposition==='REVIEW_ONLY'?[]:[output.reason];
 }else{
  const value=extractFields(item.raw,item.family as ConcreteFormat,{
   csvColumns:item.csvColumns??'',csvDelimiter:',',
  } as ParserDraft);
  fields=value.fields;errors=value.errors;
 }
 const rawSource=item.family==='cef'?arbitrateIndependentNonJson(item.raw):
   item.family==='leef'?arbitrateIndependentLeef(item.raw):null;
 const sourceDisposition=rawSource?.disposition??'NOT_CHECKED_WITH_SOURCE_OBSERVER';
 if(rawSource){
  if(rawSource.disposition.startsWith('REVIEW_ONLY'))sourceReview++;
  else sourceAbstain++;
 }
 const matching=item.mustHave?
   Object.entries(item.mustHave).every(([name,expected])=>fields[name]===expected):false;
 const needsReview=Boolean(item.requireReview);
 let verdict:'NARROW_PASS'|'NARROW_MISSING'|'FALSE_COMPLETE_RISK'|'REVIEWED_OR_REJECTED';
 if(needsReview){
  verdict=errors.length?'REVIEWED_OR_REJECTED':'FALSE_COMPLETE_RISK';
  if(errors.length)review++;else unsafe++;
 }else if(matching&&errors.length===0){verdict='NARROW_PASS';exact++;}
 else{verdict='NARROW_MISSING';missing++;}
 rows.push({id:item.id,family:item.family,reference:item.spec,verdict,
   sourceObserver:sourceDisposition,errorCount:errors.length,
   completeClaim:errors.length===0,reason:item.requireReview??'narrow-source-claim'});
}
const counts={normativeDerivedCases:suite.cases.length,narrowExact:exact,
  narrowMissing:missing,reviewedOrRejected:review,falseCompleteRisk:unsafe,
  cefOrLeefSourceReview:sourceReview,cefOrLeefSourceAbstain:sourceAbstain};
const result={referenceFixtureSha256:digest,
 source:'AUTHOR_DERIVED_NORMATIVE_PROBES_NOT_INDEPENDENT_MANUFACTURER_LOGS',
 implementation:'UNCHANGED_PR52_BASELINE_PRODUCT_BROWSER_AND_SOURCE_OBSERVERS',
 counts,details:rows,originalCaseLogValuesPrinted:false,
 nativeFluentdOrStellar:'NOT_VERIFIED',wholeEventFP:'UNSCORABLE'};
console.log('P0_STD_NORMATIVE_BASELINE '+JSON.stringify(result));
if(rows.length!==suite.cases.length||new Set(rows.map(r=>r.id)).size!==rows.length||
 counts.narrowExact+counts.narrowMissing+counts.reviewedOrRejected+
 counts.falseCompleteRisk!==suite.cases.length)process.exitCode=1;
