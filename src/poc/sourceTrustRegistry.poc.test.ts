import {describe,expect,it} from 'vitest';
import {scanKeyValues,scanPrefixedKeyValues} from './losslessLexer';
import {assessPinnedSourceCandidate,pinnedTrustRegistrySummary} from './sourceTrustRegistry';

const raw='198.51.100.4 id=firewall msg="alpha" msg="beta" action=block';
const id='synthetic/test-prefix-repeated#1';
const fixture=scanPrefixedKeyValues(raw,0)!;

describe('repo-pinned, explicitly unreviewed source trust registry',()=>{
  it('checks registry cardinality without shipping original public fixture values',()=>{
    expect(pinnedTrustRegistrySummary()).toEqual({
      contract:'parser-studio.source-trust-registry.v0.1',entries:9,
      independentLexical:8,syntheticControls:1,
      humanApproved:0,rawLogsCommitted:false,
    });
  });

  it('matches only a repo-pinned source, ordered values, raw bytes and duplicate keys',async()=>{
    expect(await assessPinnedSourceCandidate(id,fixture)).toMatchObject({
      fixtureId:id,
      outcome:'PINNED_LEXICAL_MATCH_UNREVIEWED',sourceRawPreserved:true,
      oracleStage:'SYNTHETIC_CONTROL_ONLY',
      orderedSourceFieldsMatched:4,sourceGrammarApproved:false,
      semanticMappingApproved:false,nativeRuntimeApproved:false,
      productPromotionAllowed:false,requiresIndependentReview:true,
    });
  });

  it('rejects unknown fixtures and self-declared independent source strings',async()=>{
    expect((await assessPinnedSourceCandidate(
      'any-other-user-claimed-independent-fixture',fixture,
    )).outcome).toBe('NOT_ENROLLED');
    expect((await assessPinnedSourceCandidate(
      'sonicwall_firewall/test-general.log#27',fixture,
    )).outcome).toBe('SOURCE_REFERENCE_MISMATCH');
  });

  it('detects altered raw source, wrong ordered values, and lost duplicate occurrence',async()=>{
    const altered=scanPrefixedKeyValues(raw.replace('block','allow'),0)!;
    expect((await assessPinnedSourceCandidate(id,altered)).outcome)
      .toBe('SOURCE_REFERENCE_MISMATCH');

    const wrongOrder=structuredClone(fixture);
    wrongOrder.fields=[wrongOrder.fields[1]!,wrongOrder.fields[0]!,
      ...wrongOrder.fields.slice(2)];
    expect((await assessPinnedSourceCandidate(id,wrongOrder)).outcome)
      .toBe('INVALID_CANDIDATE');

    const lost=structuredClone(fixture);
    lost.fields.splice(2,1);
    expect((await assessPinnedSourceCandidate(id,lost)).outcome)
      .toBe('INVALID_CANDIDATE');
  });

  it('rejects passing the right source through an unreviewed alternate grammar',async()=>{
    const source='id=firewall msg="alpha" msg="beta" action=block';
    const kv=scanKeyValues(source,0,'space',{preserveRepeated:true});
    expect(kv).not.toBeNull();
    expect((await assessPinnedSourceCandidate(id,kv!)).outcome)
      .toBe('INVALID_CANDIDATE');
  });

  it('rejects tampered decoded values even when SHA of original raw has not changed',async()=>{
    const mutated=structuredClone(fixture);
    mutated.fields[0]!.value='compromised';
    expect((await assessPinnedSourceCandidate(id,mutated)).outcome)
      .toBe('INVALID_CANDIDATE');
  });
});
