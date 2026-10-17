import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {scanPrefixedKeyValues} from '../../src/poc/losslessLexer';
import {inspectSourceNormalization,type MappingReviewStatus}
  from '../../src/poc/sourceNormalizationBoundary';

interface Source {id:string;raw:string;source:string}
const root=path.join(os.homedir(),'.local/state/parserstudio-lossless-fresh-20261017');
const metadata=JSON.parse(fs.readFileSync(path.join(root,'manifest.json'),'utf8')) as
  {records_sha256:string};
if(metadata.records_sha256!=='70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039')
  throw Error('Pinned source corpus identity mismatch');
const rows=JSON.parse(fs.readFileSync(path.join(root,'records.json'),'utf8')) as Source[];
const ids=Object.keys(JSON.parse(fs.readFileSync(
  path.join(root,'oracle-prefixed-development.json'),'utf8')) as Record<string,unknown>);
if(ids.length!==8)throw Error('Expected exactly eight independently tokenized examples');
const byId=new Map(rows.map(item=>[item.id,item]));
const dispositions:Record<MappingReviewStatus,number>={
  REVIEWABLE_TYPE_MATCH:0,SOURCE_REFERENCE_UNVERIFIED:0,FIELD_NOT_IN_SOURCE:0,
  REPEATED_SOURCE_FIELD:0,SOURCE_FIELD_REUSED:0,TARGET_COLLISION:0,
  TARGET_NOT_MAPPABLE:0,VALUE_TYPE_MISMATCH:0,INVALID_REVIEW_REQUEST:0,
};
let events=0,requests=0,sourceCertified=0,unsafePromotion=0;
for(const fixtureId of ids){
  const sample=byId.get(fixtureId);
  if(!sample)throw Error('Expected source event ID is missing');
  const candidate=scanPrefixedKeyValues(sample.raw,0);
  if(!candidate)throw Error('Pinned original no longer lexes');
  const review=await inspectSourceNormalization(fixtureId,candidate,[
    {sourceKey:'src',targetField:'srcip'},
    {sourceKey:'dst',targetField:'dstip'},
    {sourceKey:'fw_action',targetField:'action'},
  ]);
  events++;
  requests+=review.requested;
  if(review.sourceOracleStatus==='PINNED_LEXICAL_MATCH_UNREVIEWED')sourceCertified++;
  if(review.productPromotionAllowed||review.normalizedMappingApproved||
     review.sourceGrammarApproved||review.nativeRuntimeVerified)
    unsafePromotion++;
  for(const item of review.results){
    dispositions[item.status]++;
    if(item.productPromotionAllowed||item.normalizedMappingApproved||
      item.sourceMeaningApproved||item.nativeRuntimeVerified)unsafePromotion++;
  }
}
const result={
  manifest:'70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039',
  inspectedEvents:events,pinnedLexicalSourceMatches:sourceCertified,
  proposedSourceToTargetAssignments:requests,dispositions,
  semanticMappingsApproved:0,nativeRuntimeVerified:0,
  productPromotions:unsafePromotion,
  precisionRecallScope:'NOT_SCORED_NO_INDEPENDENT_SEMANTIC_REFERENCE',
};
console.log('SOURCE_NORMALIZATION_REVIEW '+JSON.stringify(result));
if(events!==8||requests!==24||sourceCertified!==8||
  Object.values(dispositions).reduce((a,b)=>a+b,0)!==24||unsafePromotion!==0)
  process.exitCode=1;
