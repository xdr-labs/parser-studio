import {sha256Utf8Hex} from '../sha256';
import {replayCandidate} from './grammarFunnel';
import type {LexicalCandidate} from './losslessLexer';

/**
 * A reviewable fixture-level *source value* certificate.
 * This never authorizes semantic mapping, parser export, or native execution.
 * Caller-supplied oracle claims require a separately audited provenance trail.
 */
export interface IndependentSourceReference {
  originalSha256:string;
  upstreamRevision:string;
  fixtureId:string;
  authority:'independent_source_oracle';
  orderedFields:Array<readonly [string,string]>;
  expectedPrefix?:string;
}

export interface SourceEvidenceDecision {
  status:'source_value_exact'|'unverified'|'source_mismatch';
  sourceRawPreserved:boolean;
  reviewedFieldCount:number;
  mappingVerified:false;
  nativeRuntimeVerified:false;
  productPromotionAllowed:false;
  requiresHumanReview:boolean;
  reason:string;
}

const sourceOnly=(status:SourceEvidenceDecision['status'],reason:string):
  SourceEvidenceDecision=>({
    status,sourceRawPreserved:false,reviewedFieldCount:0,mappingVerified:false,
    nativeRuntimeVerified:false,productPromotionAllowed:false,
    requiresHumanReview:true,reason,
  });

/**
 * Require exact per-record source identity and ordered independent field
 * matches. A field-exact partial event is still not a fully parsed event.
 */
export async function reviewSourceEvidence(
  candidate:LexicalCandidate,
  independent?:IndependentSourceReference,
):Promise<SourceEvidenceDecision>{
  const replay=replayCandidate(candidate);
  if(!replay||!replay.tokenSpansReplayed||candidate.naming!=='source')
    return sourceOnly('unverified','No replayable source-named candidate');
  if(!independent)return sourceOnly('unverified','Independent field oracle not provided');
  if(independent.authority!=='independent_source_oracle'||
     !/^[a-f0-9]{64}$/.test(independent.originalSha256)||
     !/^[a-f0-9]{40}$/.test(independent.upstreamRevision)||
     !independent.fixtureId||independent.fixtureId.length>512||
     !independent.orderedFields.length||independent.orderedFields.length>256)
    return sourceOnly('unverified','Source provenance or oracle declaration is invalid');
  const checksum=await sha256Utf8Hex(candidate.sourceRaw);
  if(checksum!==independent.originalSha256)
    return sourceOnly('source_mismatch','Source bytes differ from independent reference');
  const originalPrefix=candidate.prefixSpan?
    candidate.sourceRaw.slice(candidate.prefixSpan.start,candidate.prefixSpan.end):undefined;
  if(originalPrefix!==independent.expectedPrefix)
    return sourceOnly('source_mismatch','Unparsed source prefix differs');
  if(candidate.fields.length!==independent.orderedFields.length||
    !candidate.fields.every((field,index)=>{
      const reference=independent.orderedFields[index];
      return reference!==undefined&&
        reference[0]===field.key&&reference[1]===field.value;
    }))return sourceOnly('source_mismatch','Ordered source field values differ');
  return {
    status:'source_value_exact',
    sourceRawPreserved:true,
    reviewedFieldCount:candidate.fields.length,
    mappingVerified:false,nativeRuntimeVerified:false,
    productPromotionAllowed:false,
    requiresHumanReview:true,
    reason:replay.fullBodyCovered?
      'Exact field-value source oracle; no semantic or runtime certification':
      'Exact source fields but partial record or duplicate keys require review',
  };
}
