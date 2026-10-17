import {describe,expect,it} from 'vitest';
import {classifyVendorSourceReview,type VendorReviewInput} from './vendorProfileReviewGate';

const qualified:VendorReviewInput={
  lexicalCandidate:true,originalSourceShaMatches:true,exactRawRetained:true,
  independentSourceVerdict:'EXACT',existingVendorProfile:'PASS',
};
describe('isolated accuracy-first vendor source qualification gate',()=>{
  it('allows only exact source+profile evidence to reach review, never product approval',()=>{
    const o=classifyVendorSourceReview(qualified);
    expect(o.disposition).toBe('SOURCE_EXACT_PROFILE_REVIEW_ONLY');
    expect(o.originalSourceVerified).toBe(true);
    expect(o.canAutoPromote).toBe(false);
    expect(o.manufacturerSemantics).toBe('NOT_CERTIFIED');
    expect(o.nativeTarget).toBe('NOT_VERIFIED');
  });
  it('does not treat a generic syntactic KV match as vendor profile success',()=>{
    const o=classifyVendorSourceReview({...qualified,existingVendorProfile:'FAIL'});
    expect(o.disposition).toBe('EXISTING_VENDOR_PROFILE_VETO');
    expect(o.originalSourceVerified).toBe(false);
  });
  it('does not fabricate field correctness without an independent source oracle',()=>{
    const o=classifyVendorSourceReview({...qualified,independentSourceVerdict:'UNSCORED'});
    expect(o.disposition).toBe('PROFILE_MATCH_UNSCORED');
    expect(o.originalSourceVerified).toBe(false);
  });
  it('refuses matching field count when source values disagree',()=>{
    const o=classifyVendorSourceReview({...qualified,independentSourceVerdict:'MISMATCH'});
    expect(o.disposition).toBe('SOURCE_FIELD_MISMATCH');
  });
  it('does not declare vendor compatibility from independent source values alone',()=>{
    const o=classifyVendorSourceReview({...qualified,existingVendorProfile:'UNKNOWN'});
    expect(o.disposition).toBe('SOURCE_EXACT_VENDOR_UNREVIEWED');
    expect(o.originalSourceVerified).toBe(true);
    expect(o.canAutoPromote).toBe(false);
  });
  it('keeps unscored, unknown family grammar review-only',()=>{
    const o=classifyVendorSourceReview({...qualified,
      existingVendorProfile:'UNKNOWN',independentSourceVerdict:'UNSCORED'});
    expect(o.disposition).toBe('GRAMMAR_ONLY_UNSCORED');
  });
  it('blocks raw drift even if fields match',()=>{
    const o=classifyVendorSourceReview({...qualified,exactRawRetained:false});
    expect(o.disposition).toBe('SOURCE_IDENTITY_REJECTED');
  });
  it('blocks original SHA drift even if fields and profile match',()=>{
    const o=classifyVendorSourceReview({...qualified,originalSourceShaMatches:false});
    expect(o.disposition).toBe('SOURCE_IDENTITY_REJECTED');
  });
  it('does not invent a KV candidate from an unsupported grammar',()=>{
    const o=classifyVendorSourceReview({...qualified,lexicalCandidate:false});
    expect(o.disposition).toBe('NOT_KV_CANDIDATE');
  });
});
