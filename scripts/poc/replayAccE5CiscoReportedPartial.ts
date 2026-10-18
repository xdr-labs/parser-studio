/** Read-only private original-vs-Oracle replay for one third-party FTD report.
 *
 * The reporter's raw field contains a fused/truncated Syslog record.
 * Only the independently pinned, complete early label:value source span is
 * reviewed. Do not publish private values or claim manufacturer packet truth.
 */
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {inspectBoundedColonLabels} from '../../src/poc/accE5PartialColonSource';

const hash=(source:Uint8Array)=>createHash('sha256').update(source).digest('hex');
const state=join(homedir(),'.local/state');
const base=join(state,'parserstudio-acc-e5-cisco-ftd-partial-source-20261018');
const inputs=join(state,'parserstudio-acc-e3-public-negative-review-20261018');
const frozen=readFileSync(join(base,'independent-reporter-partial-oracle.json'));
if(hash(frozen)!=='9d9287bc2854ef776bb920d003765aea69ed1ab2a471ae7da3a9091edb213ecf')
  throw new Error('Independent pre-implementation Oracle checksum drift');
const truth=JSON.parse(frozen.toString('utf8')) as {
  fullSourceSha256:string;bodyStartByte:number;
  independentlySelectedReviewEndByte:number;firstEmbeddedPriByte:number;
  residualSha256:string;fields:Array<{
    name:string;occurrence:number;rawLexeme:string;lexicalValue:string;
    nameStartByte:number;nameEndByte:number;valueStartByte:number;valueEndByte:number;
  }>;
};
const reported=JSON.parse(readFileSync(join(inputs,'ftd_reported_event_original.json'),'utf8')) as {
  sourceText:string;
};
const source=new TextEncoder().encode(reported.sourceText);
if(hash(source)!==truth.fullSourceSha256||source.length!==1154||
   truth.bodyStartByte!==49||truth.independentlySelectedReviewEndByte!==959||
   truth.firstEmbeddedPriByte!==971)
  throw new Error('Source size/boundary/provenance drift');
const b=source.subarray(truth.bodyStartByte,truth.independentlySelectedReviewEndByte);
const review=inspectBoundedColonLabels({
  sourceBytes:source,sourceSha256:truth.fullSourceSha256,
  analysisScope:'EXPLICIT_SUBRECORD_SOURCE_SLICE',
  boundedStartByte:truth.bodyStartByte,
  boundedEndByte:truth.independentlySelectedReviewEndByte,
  boundedSliceSha256:hash(b),
});
if(review.disposition!=='REVIEW_ONLY_PARTIAL_LABELS'||
   review.sourceComplete||review.canAutoPromote||
   review.independentOracleCertified||
   review.unreviewedSuffixBytes!==195||
   review.originalDeviceIdentity!=='NOT_ATTESTED'||
   review.fields.length!==truth.fields.length)
  throw new Error('Partial source review boundary mismatch');
for(const [index,field] of review.fields.entries()){
  const reference=truth.fields[index];
  if(!reference||field.name!==reference.name||
     field.occurrence!==reference.occurrence||
     field.rawLexeme!==reference.rawLexeme||
     field.sourceValue!==reference.lexicalValue||
     field.nameStartByte!==reference.nameStartByte||
     field.nameEndByte!==reference.nameEndByte||
     field.valueStartByte!==reference.valueStartByte||
     field.valueEndByte!==reference.valueEndByte)
    throw new Error('Independent field source/span mismatch at ordinal '+index);
}
const trailing=source.subarray(truth.independentlySelectedReviewEndByte);
if(hash(trailing)!==truth.residualSha256)
  throw new Error('Trailing unqualified collector source bytes changed');
process.stdout.write(JSON.stringify({
  sourceQualifier:'THIRD_PARTY_REPORTER_COLLECTOR_TEXT_NOT_DEVICE_PACKET',
  publicSource:'https://github.com/elastic/integrations/issues/15204',
  rawBytes:source.length,
  explicitPartialBodyStartByte:truth.bodyStartByte,
  explicitPartialBodyEndByte:truth.independentlySelectedReviewEndByte,
  firstEmbeddedPriByte:truth.firstEmbeddedPriByte,
  exactIndependentOriginalNameValueByteClaims:review.fields.length,
  unreviewedSuffixBytes:review.unreviewedSuffixBytes,
  sourceComplete:review.sourceComplete,canAutoPromote:review.canAutoPromote,
  manufacturerWireAccuracyDenominator:0,
},null,2)+'\n');
