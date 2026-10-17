import {describe,expect,it} from 'vitest';
import {scanKeyValues,scanPrefixedKeyValues} from './losslessLexer';
import {inspectSourceNormalization,sourceValueSupportsMapping} from './sourceNormalizationBoundary';

const raw='198.51.100.4 id=firewall msg="alpha" msg="beta" action=block';
const pinned='synthetic/test-prefix-repeated#1';
const candidate=scanPrefixedKeyValues(raw,0)!;

describe('unverified source semantics / official Stellar type boundary',()=>{
  it('permits only a type-compatible REVIEW suggestion even with an exact pinned source',async()=>{
    const response=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'action',targetField:'action'},
    ]);
    expect(response).toMatchObject({
      contract:'parser-studio.source-normalization-review.v0.1',
      sourceOracleStatus:'PINNED_LEXICAL_MATCH_UNREVIEWED',
      requested:1,reviewableTypeMatches:1,rejectedOrUnverified:0,
      pinnedCatalogRevision:'7.0.xs',
      sourceGrammarApproved:false,sourceMeaningApproved:false,
      normalizedMappingApproved:false,nativeRuntimeVerified:false,
      productPromotionAllowed:false,requiresHumanReview:true,
      results:[{sourceKey:'action',targetField:'action',
        status:'REVIEWABLE_TYPE_MATCH',typeCompatible:true,
        documentedTargetType:'string',sourceFieldOccurrences:1,
        catalogRevision:'7.0.xs',sourceMeaningApproved:false,
        normalizedMappingApproved:false,productPromotionAllowed:false}],
    });
    const serialized=JSON.stringify(response);
    expect(serialized).not.toContain('198.51.100.4');
    expect(serialized).not.toContain('"alpha"');
    expect(serialized).not.toContain('"block"');
  });

  it('rejects unpinned sources even with valid Stellar field names and scalar values',async()=>{
    const valid=scanKeyValues('srcip=192.0.2.1 dstport=443',0,'space')!;
    const result=await inspectSourceNormalization('user-self-certified-fixture',valid,[
      {sourceKey:'srcip',targetField:'srcip'},
    ]);
    expect(result).toMatchObject({sourceOracleStatus:'NOT_ENROLLED',
      reviewableTypeMatches:0,
      results:[{status:'SOURCE_REFERENCE_UNVERIFIED'}]});
  });

  it('never collapses repeated source fields into a single mapped target',async()=>{
    const r=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'msg',targetField:'message'},
    ]);
    expect(r.results[0]).toMatchObject({status:'REPEATED_SOURCE_FIELD',
      sourceFieldOccurrences:2,productPromotionAllowed:false});
  });

  it('refuses unsupported targets and incorrectly typed values',async()=>{
    const r=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'action',targetField:'srcport'},
      {sourceKey:'id',targetField:'event_id'},
      {sourceKey:'id',targetField:'unsupported_custom_field'},
    ]);
    expect(r.results.map(x=>x.status)).toEqual([
      'VALUE_TYPE_MISMATCH','SOURCE_FIELD_REUSED','SOURCE_FIELD_REUSED',
    ]);
    const alone=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'id',targetField:'event_id'},
    ]);
    expect(alone.results[0]?.status).toBe('VALUE_TYPE_MISMATCH');
    const missing=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'id',targetField:'unsupported_custom_field'},
    ]);
    expect(missing.results[0]?.status).toBe('TARGET_NOT_MAPPABLE');
  });

  it('rejects collisions and nested destination overlaps before a type claim',async()=>{
    const r=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'id',targetField:'action'},
      {sourceKey:'action',targetField:'action'},
    ]);
    expect(r.results.map(x=>x.status)).toEqual([
      'TARGET_COLLISION','TARGET_COLLISION',
    ]);
  });

  it('rejects unknown source field names and unsafe review assignments',async()=>{
    const missing=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'no_such_source_field',targetField:'action'},
    ]);
    expect(missing.results[0]?.status).toBe('FIELD_NOT_IN_SOURCE');
    const invalid=await inspectSourceNormalization(pinned,candidate,[
      {sourceKey:'__proto__',targetField:'action'},
    ]);
    expect(invalid.results[0]?.status).toBe('INVALID_REVIEW_REQUEST');
  });

  it('rejects modified source without leaking values to normalized results',async()=>{
    const mutated=scanPrefixedKeyValues(raw.replace('action=block','action=allow'),0)!;
    const r=await inspectSourceNormalization(pinned,mutated,[
      {sourceKey:'action',targetField:'action'},
    ]);
    expect(r).toMatchObject({sourceOracleStatus:'SOURCE_REFERENCE_MISMATCH',
      results:[{status:'SOURCE_REFERENCE_UNVERIFIED'}],
      normalizedMappingApproved:false});
  });

  it('rejects absent fields and unsupported timestamp guesses as mapping type evidence',()=>{
    expect(sourceValueSupportsMapping('action','string','')).toBe(false);
    expect(sourceValueSupportsMapping('action','string','N/A')).toBe(false);
    expect(sourceValueSupportsMapping('action','string','-')).toBe(false);
    expect(sourceValueSupportsMapping('srcip','ip','192.0.2.7')).toBe(true);
    expect(sourceValueSupportsMapping('srcip','ip','invalid-ip')).toBe(false);
    expect(sourceValueSupportsMapping('srcport','integer','65536')).toBe(false);
    expect(sourceValueSupportsMapping('timestamp','timestamp','Oct 17 12:00:00')).toBe(false);
    expect(sourceValueSupportsMapping('timestamp','timestamp','2026-10-17T12:00:00')).toBe(false);
    expect(sourceValueSupportsMapping('timestamp','timestamp','2026-10-17T12:00:00Z')).toBe(true);
  });

  it('sets hard input bounds and deterministic no-request results',async()=>{
    await expect(inspectSourceNormalization(pinned,candidate,new Array(257).fill({
      sourceKey:'action',targetField:'action',
    }))).rejects.toThrow('bounded');
    const result=await inspectSourceNormalization(pinned,candidate,[]);
    expect(result).toMatchObject({requested:0,reviewableTypeMatches:0,
      rejectedOrUnverified:0,productPromotionAllowed:false,results:[]});
  });
});
