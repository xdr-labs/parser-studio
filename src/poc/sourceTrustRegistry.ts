import {sha256Utf8Hex} from '../sha256';
import type {LexicalCandidate} from './losslessLexer';
import {replayCandidate} from './grammarFunnel';
import sourceTrustPins from './sourceTrustPins.json';

/**
 * Repo-pinned fixture provenance, not a user-supplied approval declaration.
 * Source IDs and source-value digests were generated using independent
 * fixture tokenization, without committing any raw upstream security logs.
 *
 * A MATCH proves agreement with the pinned lexical reference only.
 * It explicitly does not approve a source grammar, Stellar mapping or native
 * compiler, even if the input claims a higher authority in its payload.
 */
export type SourceTrustOutcome=
  'PINNED_LEXICAL_MATCH_UNREVIEWED'|'NOT_ENROLLED'|'SOURCE_REFERENCE_MISMATCH'|'INVALID_CANDIDATE';
export interface SourceTrustAssessment {
  outcome:SourceTrustOutcome;
  fixtureId:string;
  sourceRawPreserved:boolean;
  orderedSourceFieldsMatched:number;
  oracleStage:'INDEPENDENT_LEXICAL_UNREVIEWED'|'SYNTHETIC_CONTROL_ONLY'|'NONE';
  sourceGrammarApproved:false;
  semanticMappingApproved:false;
  nativeRuntimeApproved:false;
  productPromotionAllowed:false;
  requiresIndependentReview:true;
  reason:string;
}

const noop=(fixtureId:string,outcome:SourceTrustOutcome,reason:string):
  SourceTrustAssessment=>({
    fixtureId,outcome,reason,sourceRawPreserved:false,
    orderedSourceFieldsMatched:0,oracleStage:'NONE',
    sourceGrammarApproved:false,semanticMappingApproved:false,
    nativeRuntimeApproved:false,productPromotionAllowed:false,
    requiresIndependentReview:true,
  });

const hexSha=(value:string)=>/^[a-f0-9]{64}$/.test(value);
function validPinnedRegistry():boolean{
  const r=sourceTrustPins;
  if(r.contract!=='parser-studio.source-trust-registry.v0.1'||
     r.reviewState!=='NOT_HUMAN_REVIEWED'||
     r.upstreamRepository!=='https://github.com/elastic/integrations'||
     !/^[a-f0-9]{40}$/.test(r.upstreamRevision)||
     !hexSha(r.recordSetSha256)||r.entries.length!==9)return false;
  const seen=new Set<string>();
  for(const entry of r.entries){
    if(!entry.fixtureId||entry.fixtureId.length>256||
      !hexSha(entry.sourceSha256)||!hexSha(entry.orderedFieldsSha256)||
      !hexSha(entry.prefixSha256)||
      !Number.isInteger(entry.expectedFieldCount)||entry.expectedFieldCount<2||
      entry.expectedFieldCount>256||
      !Number.isInteger(entry.expectedDuplicateCount)||entry.expectedDuplicateCount<0||
      entry.expectedDuplicateCount>=entry.expectedFieldCount||
      entry.grammar!=='prefixed_kv_space'||
      !['INDEPENDENT_LEXICAL_UNREVIEWED','SYNTHETIC_CONTROL_ONLY'].includes(entry.oracleStage)||
      seen.has(entry.fixtureId))return false;
    seen.add(entry.fixtureId);
  }
  return true;
}

/** Read-only metadata only, never includes event source text or expected values. */
export function pinnedTrustRegistrySummary():{
  contract:string;entries:number;independentLexical:number;syntheticControls:number;
  humanApproved:0;rawLogsCommitted:false;
}{
  if(!validPinnedRegistry())throw Error('Pinned source-trust registry is invalid');
  return {
    contract:sourceTrustPins.contract,
    entries:sourceTrustPins.entries.length,
    independentLexical:sourceTrustPins.entries.filter(entry=>
      entry.oracleStage==='INDEPENDENT_LEXICAL_UNREVIEWED').length,
    syntheticControls:sourceTrustPins.entries.filter(entry=>
      entry.oracleStage==='SYNTHETIC_CONTROL_ONLY').length,
    humanApproved:0,rawLogsCommitted:false,
  };
}

/**
 * A runtime caller supplies only a source candidate and an upstream fixture ID.
 * It cannot invent or extend source-value reference hashes or review authority.
 */
export async function assessPinnedSourceCandidate(
  fixtureId:string,candidate:LexicalCandidate,
):Promise<SourceTrustAssessment>{
  if(!validPinnedRegistry())
    return noop(fixtureId,'INVALID_CANDIDATE','Repository-owned trust catalog is invalid');
  const matched=sourceTrustPins.entries.find(entry=>entry.fixtureId===fixtureId);
  if(!matched)
    return noop(fixtureId,'NOT_ENROLLED','No repository-pinned independent source reference');
  const replay=replayCandidate(candidate);
  if(!replay||!replay.tokenSpansReplayed||candidate.naming!=='source'||
     candidate.grammar!==matched.grammar||!candidate.prefixSpan)
    return noop(fixtureId,'INVALID_CANDIDATE','Source grammar is not fully replayable');
  const fields=candidate.fields.map(field=>[field.key,field.value]);
  const [rawSha,fieldsSha,prefixSha]=await Promise.all([
    sha256Utf8Hex(candidate.sourceRaw),
    sha256Utf8Hex(JSON.stringify(fields)),
    sha256Utf8Hex(candidate.sourceRaw.slice(
      candidate.prefixSpan.start,candidate.prefixSpan.end)),
  ]);
  const expectedDuplicates=candidate.fields.length-
    new Set(candidate.fields.map(field=>field.key)).size;
  if(rawSha!==matched.sourceSha256||
     fieldsSha!==matched.orderedFieldsSha256||
     prefixSha!==matched.prefixSha256||
     candidate.fields.length!==matched.expectedFieldCount||
     expectedDuplicates!==matched.expectedDuplicateCount)
    return noop(fixtureId,'SOURCE_REFERENCE_MISMATCH',
      'Original bytes, ordered values, prefix or repeated fields disagree with the pinned source');
  return {
    outcome:'PINNED_LEXICAL_MATCH_UNREVIEWED',
    fixtureId,sourceRawPreserved:true,
    orderedSourceFieldsMatched:candidate.fields.length,
    oracleStage:matched.oracleStage as
      'INDEPENDENT_LEXICAL_UNREVIEWED'|'SYNTHETIC_CONTROL_ONLY',
    sourceGrammarApproved:false,semanticMappingApproved:false,
    nativeRuntimeApproved:false,productPromotionAllowed:false,
    requiresIndependentReview:true,
    reason:matched.oracleStage==='SYNTHETIC_CONTROL_ONLY'?
      'Synthetic regression fixture, not a source grammar approval':
      'Matches independently tokenized source fixture only; human review and mapping remain pending',
  };
}
