import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {scanPrefixedKeyValues} from '../../src/poc/losslessLexer';
import {extractCompositeFromSource,reviewPinnedCompositeEndpoint}
  from '../../src/poc/compositeEndpointGrammar';

type RecordInput={id:string;source:string;raw:string};
type Reference={eventId:string;field:string;sourceSha256:string;
  parts:Array<['ipv4'|'port'|'interface'|'resolvedHost',string]>};
const root=path.join(os.homedir(),'.local/state/parserstudio-lossless-fresh-20261017');
const manifest=JSON.parse(fs.readFileSync(path.join(root,'manifest.json'),'utf8')) as
  {records_sha256:string};
if(manifest.records_sha256!=='70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039')
  throw Error('Pinned corpus identity drift');
const samples=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as RecordInput[];
const byId=new Map(samples.map(row=>[row.id,row]));
const oracle=JSON.parse(fs.readFileSync(
  path.join(root,'oracle-composite-endpoint.json'),'utf8')) as Record<string,Reference>;
if(Object.keys(oracle).length!==16)throw Error('Expected sixteen original endpoints');
let accepted=0,exact=0,negativeRejected=0,unapproved=0,components=0;
const errors:string[]=[];
for(const [id,reference] of Object.entries(oracle)){
  const source=byId.get(reference.eventId);
  if(!source||id!==reference.eventId+'/'+reference.field)throw Error('Original ID is missing');
  const digest=crypto.createHash('sha256').update(source.raw).digest('hex');
  if(digest!==reference.sourceSha256)throw Error('Independent source identity changed');
  const candidate=scanPrefixedKeyValues(source.raw,0);
  if(!candidate)throw Error('Pinned original no longer lexes');
  const matching=candidate.fields.filter(f=>f.key===reference.field);
  if(matching.length!==1)throw Error('Ambiguous source field');
  const parsed=extractCompositeFromSource(source.raw,matching[0]!);
  if(!parsed){
    errors.push(id+':lexical_reject');continue;
  }
  exact++;
  if(parsed.parts.length!==reference.parts.length||
    !parsed.parts.every((part,i)=>part.role===reference.parts[i]?.[0]&&
      part.value===reference.parts[i]?.[1]&&
      source.raw.slice(part.sourceSpan.start,part.sourceSpan.end)===part.value))
    errors.push(id+':field_value_or_span_mismatch');
  components+=parsed.parts.length;
  const role=reference.field==='src'?'source':'destination';
  const review=await reviewPinnedCompositeEndpoint(reference.eventId,candidate,reference.field,role);
  if(review.disposition==='REVIEWABLE_COMPONENTS_UNAPPROVED'&&
     review.byteRanges.length===reference.parts.length&&
     review.componentCount===reference.parts.length)accepted++;
  else errors.push(id+':pinned_review_did_not_match');
  if(!review.endpointSemanticApproved&&!review.normalizationApproved&&
     !review.nativeRuntimeVerified&&!review.productPromotionAllowed)unapproved++;
  const changed=source.raw.replace(
    reference.field+'='+matching[0]!.value,
    reference.field+'=999.999.999.999:443:X0');
  const mutated=scanPrefixedKeyValues(changed,0);
  const result=mutated?await reviewPinnedCompositeEndpoint(
    reference.eventId,mutated,reference.field,role):null;
  if(result===null||result.disposition!=='REVIEWABLE_COMPONENTS_UNAPPROVED')
    negativeRejected++;
  else errors.push(id+':mutated_source_was_approved');
}
const report={events:8,sourceCompositeValues:Object.keys(oracle).length,
  exactIndependentComponents:exact,componentParts:components,
  typedSourceTargetReviewCandidates:accepted*2,
  fullPinnedSourceReviewMatches:accepted,
  malformedOrChangedSourcesRejected:negativeRejected,
  semanticOrNativeApprovals:16-unapproved,
  productPromotions:0,sourceFieldPrecisionRecall:'NOT_SCORED_IN_SAMPLE',
  errors};
console.log('COMPOSITE_ENDPOINT_ORACLE '+JSON.stringify(report));
if(errors.length||exact!==16||accepted!==16||negativeRejected!==16||
   unapproved!==16||components<48)process.exitCode=1;
