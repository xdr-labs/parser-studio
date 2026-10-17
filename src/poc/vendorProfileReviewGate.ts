/** PoC-only separation of syntax, source fidelity and vendor profile compatibility.
 *  Existing vendor profile is a veto, NOT independent manufacturer certification.
 */
export type VendorReviewDisposition=
  'NOT_KV_CANDIDATE'|'SOURCE_IDENTITY_REJECTED'|
  'EXISTING_VENDOR_PROFILE_VETO'|'SOURCE_FIELD_MISMATCH'|
  'GRAMMAR_ONLY_UNSCORED'|'PROFILE_MATCH_UNSCORED'|
  'SOURCE_EXACT_VENDOR_UNREVIEWED'|'SOURCE_EXACT_PROFILE_REVIEW_ONLY';

export type VendorReviewInput={
  lexicalCandidate:boolean;
  originalSourceShaMatches:boolean;
  exactRawRetained:boolean;
  independentSourceVerdict:'EXACT'|'MISMATCH'|'UNSCORED';
  existingVendorProfile:'PASS'|'FAIL'|'UNKNOWN';
};

export type VendorReviewResult={
  disposition:VendorReviewDisposition;
  originalSourceVerified:boolean;
  manufacturerSemantics:'NOT_CERTIFIED';
  nativeTarget:'NOT_VERIFIED';
  canAutoPromote:false;
};

export function classifyVendorSourceReview(input:VendorReviewInput):VendorReviewResult{
  const out=(disposition:VendorReviewDisposition,originalSourceVerified=false):VendorReviewResult=>({
    disposition,originalSourceVerified,
    manufacturerSemantics:'NOT_CERTIFIED',nativeTarget:'NOT_VERIFIED',canAutoPromote:false,
  });
  if(!input.lexicalCandidate)return out('NOT_KV_CANDIDATE');
  if(!input.originalSourceShaMatches||!input.exactRawRetained)
    return out('SOURCE_IDENTITY_REJECTED');
  // Existing product vendor grammar may veto a generic source-KV lexer, even if
  // a lexical token pattern looked complete. Not itself proof of vendor semantics.
  if(input.existingVendorProfile==='FAIL')
    return out('EXISTING_VENDOR_PROFILE_VETO');
  if(input.independentSourceVerdict==='MISMATCH')
    return out('SOURCE_FIELD_MISMATCH');
  if(input.independentSourceVerdict==='UNSCORED')
    return out(input.existingVendorProfile==='PASS'?
      'PROFILE_MATCH_UNSCORED':'GRAMMAR_ONLY_UNSCORED');
  return out(input.existingVendorProfile==='PASS'?
    'SOURCE_EXACT_PROFILE_REVIEW_ONLY':'SOURCE_EXACT_VENDOR_UNREVIEWED',true);
}
