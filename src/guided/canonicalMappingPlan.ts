import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {listSafeLeafPaths,countUnaddressableSourceValues} from '../fieldPaths';
import type {FieldGroup} from './contract';
import {suggestUnmappedFieldPlan,type SuggestedFieldMapping} from './fieldMappingSuggestions';
import {
  suggestNormalizationCandidatesFromSuite,
  normalizationCandidateScanStatus,
  type NormalizationCandidate,
} from './normalizationCandidates';
import {reviewNormalizationMappings,isBlockingNormalizationFinding,
  type NormalizationFindingCode} from './normalizationValidation';

/** Authoring decision contract, not a Stellar serialized output field. */
export type MappingOrigin='AUTO'|'USER_EDITED'|'APPROVED'|'REVIEW_REQUIRED'|'LEGACY_UNKNOWN';
export type MappingDisposition='MAPPED'|'SUGGESTED_OFFICIAL'|'SUGGESTED_VENDOR'|'REVIEW_REQUIRED';
export type MappingReviewReason='NO_VALID_DESTINATION'|'SUGGESTION_BUDGET'|
  'CATALOG_AMBIGUITY'|'OFFICIAL_SCAN_LIMIT'|'EXISTING_TARGET_CONFLICT'|
  'MAPPING_VALIDATION_FAILED'|'NON_CANONICAL_SOURCE';
export interface CanonicalMappingEntry {
  source:string;
  disposition:MappingDisposition;
  origin:MappingOrigin;
  target?:string;
  type?:MappingRule['type'];
  group?:FieldGroup;
  mappingId?:string;
  evidence?:{observed:number;compatible:number;total:number;catalogVerified:boolean};
  reviewReasons:readonly (MappingReviewReason|NormalizationFindingCode)[];
}
export interface CanonicalMappingPlan {
  contract:'parser-studio.mapping-plan.v1';
  entries:readonly CanonicalMappingEntry[];
  /** Every safe extracted source has exactly one decision, even when unassigned. */
  sourceCount:number;
  mappedCount:number;
  unresolvedCount:number;
  officialCandidates:readonly NormalizationCandidate[];
  vendorSuggestions:readonly SuggestedFieldMapping[];
  /** Unknown/unsafe original paths are accounted separately by the source parser. */
  unaddressableValues:number;
}
const overlaps=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
function sourceIdentity(rule:MappingRule):MappingOrigin{
  return rule.authoring?.version===1?rule.authoring.origin:'LEGACY_UNKNOWN';
}
function existingEntry(
  source:string,mapping:MappingRule,group:FieldGroup|undefined,
  errorCodes:readonly NormalizationFindingCode[],
):CanonicalMappingEntry{
  const reviewReasons=[...new Set(errorCodes)];
  return {source,disposition:reviewReasons.some(isBlockingNormalizationFinding)
    ?'REVIEW_REQUIRED':'MAPPED',
    origin:sourceIdentity(mapping),mappingId:mapping.id,target:mapping.target,
    type:mapping.type,group:group??'vendor_fields',reviewReasons};
}
/**
 * One deterministic census of source identity and all mapping alternatives.
 * Approval is not inferred from a candidate name: only explicit edit/approval
 * transitions may write a mapping to the author's draft.
 * The resulting plan is value-free; it never transports raw customer logs.
 */
export function createCanonicalMappingPlan(
  suite:SuiteResult|undefined,draft:ParserDraft,
):CanonicalMappingPlan{
  const events=suite?.events??[];
  const paths=new Set<string>();
  for(const event of events)
    for(const source of listSafeLeafPaths(event.fields))paths.add(source);
  const groups=draft.guided?.groups??{};
  const existingBySource=new Map<string,MappingRule[]>();
  for(const mapping of draft.mappings){
    const values=existingBySource.get(mapping.source)??[];
    values.push(mapping);existingBySource.set(mapping.source,values);
  }
  const proposed=suggestUnmappedFieldPlan(events.map(event=>event.fields),draft);
  const vendor=new Map(proposed.suggestions.map(item=>[item.source,item]));
  const officialCandidates=suggestNormalizationCandidatesFromSuite(suite,draft.mappings,groups);
  const official=new Map<string,NormalizationCandidate>();
  for(const candidate of officialCandidates){
    // A REVIEW result retains the ambiguity reason, but is never applied.
    official.set(candidate.source,candidate);
  }
  const errors=reviewNormalizationMappings(suite,draft.mappings,groups).findings;
  const status=normalizationCandidateScanStatus(suite);
  const occupied=draft.mappings.map(mapping=>mapping.target);
  // The official candidate provider intentionally suppresses destinations
  // occupied by another mapping. Preserve that safe suppression, but derive
  // collision evidence from a separate catalog-only pass so the canonical
  // plan explains why a source was not eligible for official normalization.
  // Never promote the diagnostic-only candidate to an actionable proposal.
  const diagnosticOfficial=occupied.length
    ?new Map(suggestNormalizationCandidatesFromSuite(suite,[],{})
      .map(candidate=>[candidate.source,candidate]))
    :new Map<string,NormalizationCandidate>();
  const entries=[...paths].sort().map(source=>{
    const mapped=existingBySource.get(source)??[];
    if(mapped.length){
      const mapping=mapped[0]!;
      const codes=errors.filter(error=>error.source===source).map(error=>error.code);
      if(mapped.length>1)codes.push('TARGET_COLLISION');
      return existingEntry(source,mapping,groups[mapping.id],codes);
    }
    const candidate=official.get(source);
    const suggestion=vendor.get(source);
    const evidenceCandidate=candidate??diagnosticOfficial.get(source);
    const collision=Boolean(evidenceCandidate&&occupied.some(target=>
      overlaps(target,evidenceCandidate.target)));
    const approved=Boolean(candidate&&candidate.confidence==='HIGH'&&candidate.safeForBulk&&
      !candidate.when&&!collision);
    const reviewReasons:MappingReviewReason[]=[];
    if(!approved&&candidate)reviewReasons.push('CATALOG_AMBIGUITY');
    if(status.exceeded)reviewReasons.push('OFFICIAL_SCAN_LIMIT');
    if(collision)reviewReasons.push('EXISTING_TARGET_CONFLICT');
    if(approved){
      return {source,origin:'REVIEW_REQUIRED' as const,
        disposition:'SUGGESTED_OFFICIAL' as const,target:candidate!.target,
        type:candidate!.type,group:candidate!.group,reviewReasons,
        evidence:{observed:candidate!.observed,compatible:candidate!.compatibleObserved,
          total:candidate!.total,catalogVerified:candidate!.catalogVerified}};
    }
    if(suggestion){
      return {source,origin:'REVIEW_REQUIRED' as const,
        disposition:'SUGGESTED_VENDOR' as const,target:suggestion.target,
        type:suggestion.type,group:suggestion.group,reviewReasons};
    }
    reviewReasons.push(proposed.suggestions.length>=100
      ?'SUGGESTION_BUDGET':proposed.unresolved.includes(source)
      ?'NO_VALID_DESTINATION':'NON_CANONICAL_SOURCE');
    return {source,origin:'REVIEW_REQUIRED' as const,
      disposition:'REVIEW_REQUIRED' as const,reviewReasons};
  });
  const mappedCount=entries.filter(entry=>entry.disposition==='MAPPED').length;
  return {contract:'parser-studio.mapping-plan.v1',entries,sourceCount:entries.length,
    mappedCount,unresolvedCount:entries.filter(entry=>entry.disposition==='REVIEW_REQUIRED').length,
    officialCandidates,vendorSuggestions:proposed.suggestions,
    unaddressableValues:events.reduce((sum,event)=>
      sum+countUnaddressableSourceValues(event.fields),0)};
}
