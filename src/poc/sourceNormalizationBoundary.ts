import type {LexicalCandidate} from './losslessLexer';
import {assessPinnedSourceCandidate,type SourceTrustOutcome} from './sourceTrustRegistry';
import {findStellarMetadataField,STELLAR_METADATA_CATALOG_PROVENANCE}
  from '../guided/stellarMetadataCatalog';
import {valueFitsNormalizationTarget} from '../guided/normalizationCandidates';

/**
 * An evidence-only mapping review. Correct source bytes and a documented
 * Stellar target TYPE do not establish correct source-field SEMANTICS.
 *
 * Never emit mapped target values, an exportable parser, or product approval.
 */
export type MappingReviewStatus=
  'REVIEWABLE_TYPE_MATCH'|'SOURCE_REFERENCE_UNVERIFIED'|'FIELD_NOT_IN_SOURCE'|
  'REPEATED_SOURCE_FIELD'|'SOURCE_FIELD_REUSED'|'TARGET_COLLISION'|
  'TARGET_NOT_MAPPABLE'|'VALUE_TYPE_MISMATCH'|'INVALID_REVIEW_REQUEST';

export interface MappingReviewRequest {
  sourceKey:string;
  targetField:string;
}

export interface MappingReviewItem {
  sourceKey:string;
  targetField:string;
  status:MappingReviewStatus;
  documentedTargetType:string|null;
  sourceFieldOccurrences:number;
  typeCompatible:boolean|null;
  catalogRevision:'7.0.xs'|null;
  sourceMeaningApproved:false;
  normalizedMappingApproved:false;
  nativeRuntimeVerified:false;
  productPromotionAllowed:false;
  requiresHumanReview:true;
}

export interface SourceNormalizationReview {
  contract:'parser-studio.source-normalization-review.v0.1';
  sourceOracleStatus:SourceTrustOutcome;
  pinnedCatalogRevision:'7.0.xs';
  pinnedCatalogUrl:string;
  sourceGrammarApproved:false;
  sourceMeaningApproved:false;
  normalizedMappingApproved:false;
  nativeRuntimeVerified:false;
  productPromotionAllowed:false;
  requiresHumanReview:true;
  requested:number;
  reviewableTypeMatches:number;
  rejectedOrUnverified:number;
  results:MappingReviewItem[];
}

const requestKey=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const invalidNames=new Set(['__proto__','prototype','constructor']);
const overlap=(first:string,second:string)=>
  first===second||first.startsWith(second+'.')||second.startsWith(first+'.');

const makeItem=(req:MappingReviewRequest,status:MappingReviewStatus,
  occurrences=0,targetType:string|null=null,compatible:boolean|null=null,
  hasCatalog=false):MappingReviewItem=>({
  sourceKey:req.sourceKey,targetField:req.targetField,status,
  documentedTargetType:targetType,sourceFieldOccurrences:occurrences,
  typeCompatible:compatible,catalogRevision:hasCatalog?'7.0.xs':null,
  sourceMeaningApproved:false,normalizedMappingApproved:false,
  nativeRuntimeVerified:false,productPromotionAllowed:false,
  requiresHumanReview:true,
});

function validName(value:string):boolean{
  if(!requestKey.test(value))return false;
  return !value.split('.').some(piece=>invalidNames.has(piece));
}

/** Empty or implicit timestamp values do not provide mapping type evidence. */
export function sourceValueSupportsMapping(
  targetField:string,documentedType:Parameters<typeof valueFitsNormalizationTarget>[1],
  value:string,
):boolean{
  const trimmed=value.trim();
  if(!trimmed||['n/a','-','unknown','null'].includes(trimmed.toLowerCase()))
    return false;
  if(documentedType==='timestamp'&&
     !/(?:Z|[+-](?:0[0-9]|1[0-4]):[0-5][0-9])$/i.test(trimmed))
    return false;
  return valueFitsNormalizationTarget(targetField,documentedType,trimmed);
}

/**
 * Only source references that passed the repo-pinned independent lexical
 * oracle can obtain reviewable type matches. Even those remain unapproved.
 */
export async function inspectSourceNormalization(
  fixtureId:string,candidate:LexicalCandidate,requests:readonly MappingReviewRequest[],
):Promise<SourceNormalizationReview>{
  if(!Array.isArray(requests)||requests.length>256)
    throw Error('A bounded list of at most 256 proposed field assignments is required');
  const source=await assessPinnedSourceCandidate(fixtureId,candidate);
  const trusted=source.outcome==='PINNED_LEXICAL_MATCH_UNREVIEWED';
  const sourceCounts=new Map<string,number>();
  for(const field of candidate.fields){
    sourceCounts.set(field.key,(sourceCounts.get(field.key)??0)+1);
  }
  const sourceRequested=new Map<string,number>();
  for(const req of requests){
    if(req&&typeof req.sourceKey==='string'&&validName(req.sourceKey))
      sourceRequested.set(req.sourceKey,(sourceRequested.get(req.sourceKey)??0)+1);
  }
  const targetCollisions=new Set<number>();
  for(let first=0;first<requests.length;first++){
    const a=requests[first];
    if(!a||typeof a.targetField!=='string'||!validName(a.targetField))continue;
    for(let second=first+1;second<requests.length;second++){
      const b=requests[second];
      if(!b||typeof b.targetField!=='string'||!validName(b.targetField))continue;
      if(overlap(a.targetField,b.targetField)){
        targetCollisions.add(first);targetCollisions.add(second);
      }
    }
  }
  const results=requests.map((req,index):MappingReviewItem=>{
    if(!req||typeof req.sourceKey!=='string'||typeof req.targetField!=='string'||
      !validName(req.sourceKey)||!validName(req.targetField))
      return makeItem({sourceKey:'INVALID',targetField:'INVALID'},'INVALID_REVIEW_REQUEST');
    const occurrences=sourceCounts.get(req.sourceKey)??0;
    if(!trusted)
      return makeItem(req,'SOURCE_REFERENCE_UNVERIFIED',occurrences);
    if(occurrences===0)return makeItem(req,'FIELD_NOT_IN_SOURCE');
    if(occurrences>1)return makeItem(req,'REPEATED_SOURCE_FIELD',occurrences);
    if((sourceRequested.get(req.sourceKey)??0)>1)
      return makeItem(req,'SOURCE_FIELD_REUSED',occurrences);
    if(targetCollisions.has(index))
      return makeItem(req,'TARGET_COLLISION',occurrences);
    const target=findStellarMetadataField(req.targetField);
    if(!target?.mappable||!target.mappingType)
      return makeItem(req,'TARGET_NOT_MAPPABLE',occurrences,
        target?.documentedTypes.join('|')??null,null,Boolean(target));
    const sourceValue=candidate.fields.find(field=>field.key===req.sourceKey)!.value;
    const valid=sourceValueSupportsMapping(req.targetField,target.mappingType,sourceValue);
    return makeItem(req,valid?'REVIEWABLE_TYPE_MATCH':'VALUE_TYPE_MISMATCH',
      occurrences,target.documentedTypes.join('|'),valid,true);
  });
  return {
    contract:'parser-studio.source-normalization-review.v0.1',
    sourceOracleStatus:source.outcome,
    pinnedCatalogRevision:'7.0.xs',
    pinnedCatalogUrl:STELLAR_METADATA_CATALOG_PROVENANCE.source,
    sourceGrammarApproved:false,sourceMeaningApproved:false,
    normalizedMappingApproved:false,nativeRuntimeVerified:false,
    productPromotionAllowed:false,requiresHumanReview:true,
    requested:requests.length,
    reviewableTypeMatches:results.filter(item=>item.status==='REVIEWABLE_TYPE_MATCH').length,
    rejectedOrUnverified:results.filter(item=>item.status!=='REVIEWABLE_TYPE_MATCH').length,
    results,
  };
}
