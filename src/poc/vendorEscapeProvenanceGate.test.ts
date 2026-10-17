import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {judgeVendorEscapeProvenance,type ProvenanceInput}
  from './vendorEscapeProvenanceGate';

const encode=(v:string)=>new TextEncoder().encode(v);
const sha=(v:Uint8Array)=>createHash('sha256').update(v).digest('hex');
const original=encode('<14>date=2026-10-17 msg="quoted unknown \\? escape" count=1');
const config=encode('Synthetic lab metadata: Fortinet FortiAnalyzer 7.2.6; fgt source');
const expected=encode('Synthetic expected value snapshot, not manufacturer certification');
const base:ProvenanceInput={
  raw:original,pinnedSourceSha256:sha(original),
  origin:'PINNED_REPO_FIXTURE',producer:'FORTIANALYZER',
  profile:'FORTIANALYZER_FGT',version:'7.2.6',
  configuration:null,semanticExpected:null,
};
const sourceAttestation=()=>({
  origin:'DEVICE_CONFIGURATION_EXPORT_CLAIM' as const,
  bytes:config,pinnedSha256:sha(config),originalSourceSha256:sha(original),
});
const semanticAttestation=()=>({
  origin:'DEVICE_WIRE_EXPECTED_CLAIM' as const,
  expectedBytes:expected,pinnedSha256:sha(expected),
  originalSourceSha256:sha(original),
});
const judge=(item:Partial<ProvenanceInput>={})=>
  judgeVendorEscapeProvenance({...base,...item});

describe('manufacturer/transport escape provenance refuses self-certified success',()=>{
  it('leaves existing public test fixtures as source-only, even with version label',()=>{
    const review=judge();
    expect(review.disposition).toBe('SOURCE_FIXTURE_NOT_DEVICE_PROOF');
    expect(review.versionRisk).toBe('FORTIANALYZER_7_2_6_ESCAPE_CHANGE');
    expect(review.manufacturerSemantics).toBe('NOT_CERTIFIED');
    expect(review.canDecodeVendorEscapes).toBe(false);
    expect(review.canAutoPromote).toBe(false);
  });
  it('distinguishes the documented FortiAnalyzer 7.2.6 escape change boundary',()=>{
    expect(judge({version:'7.2.5'}).versionRisk).toBe('VERSION_NOT_VERIFIED');
    expect(judge({version:'7.2.6'}).versionRisk)
      .toBe('FORTIANALYZER_7_2_6_ESCAPE_CHANGE');
    expect(judge({version:'7.2.10'}).versionRisk)
      .toBe('FORTIANALYZER_7_2_6_ESCAPE_CHANGE');
    expect(judge({version:'7.4.0'}).versionRisk).toBe('VERSION_NOT_VERIFIED');
    expect(judge({version:null}).versionRisk).toBe('VERSION_NOT_VERIFIED');
  });
  it('requires source SHA and rejects invalid original UTF-8 octets',()=>{
    expect(judge({pinnedSourceSha256:'a'.repeat(64)}).disposition)
      .toBe('SOURCE_IDENTITY_UNSCORABLE');
    const malformed=new Uint8Array([0x61,0x3d,0xff,0x20,0x62,0x3d,0x31]);
    expect(judge({raw:malformed,pinnedSourceSha256:sha(malformed)}).disposition)
      .toBe('SOURCE_UTF8_UNSCORABLE');
    expect(judge({raw:new Uint8Array(0)}).disposition)
      .toBe('SOURCE_IDENTITY_UNSCORABLE');
  });
  it('prevents manufacturer/format cross-routing even for valid raw byte hashes',()=>{
    expect(judge({producer:'SONICWALL'}).disposition).toBe('PRODUCER_FORMAT_CONFLICT');
    expect(judge({profile:'FORTIANALYZER_RFC5424'}).disposition)
      .toBe('WIRE_SHAPE_CONFLICT');
    expect(judge({profile:'FORTIGATE_CEF',producer:'FORTIGATE'}).disposition)
      .toBe('WIRE_SHAPE_CONFLICT');
  });
  it('does not trust a filename, documentation label or a user declaration as device configuration',()=>{
    const capture={...base,origin:'DEVICE_WIRE_CAPTURE_CLAIM' as const};
    expect(judge(capture).disposition).toBe('CONFIG_PROOF_MISSING');
    expect(judge({...capture,configuration:{
      ...sourceAttestation(),origin:'USER_DECLARED',
    }}).disposition).toBe('CONFIG_IDENTITY_UNSCORABLE');
    expect(judge({...capture,configuration:sourceAttestation(),version:null}).disposition)
      .toBe('CONFIG_PROOF_MISSING');
    expect(judge({...capture,configuration:sourceAttestation()}).disposition)
      .toBe('SEMANTIC_EXPECTATION_MISSING');
  });
  it('enforces independent original-to-config and original-to-expected bindings',()=>{
    const capture={...base,origin:'DEVICE_WIRE_CAPTURE_CLAIM' as const,
      configuration:sourceAttestation(),semanticExpected:semanticAttestation()};
    expect(judge({...capture,configuration:{
      ...sourceAttestation(),originalSourceSha256:'b'.repeat(64),
    }}).disposition).toBe('CONFIG_IDENTITY_UNSCORABLE');
    expect(judge({...capture,semanticExpected:{
      ...semanticAttestation(),originalSourceSha256:'c'.repeat(64),
    }}).disposition).toBe('CONFIG_IDENTITY_UNSCORABLE');
    expect(judge({...capture,semanticExpected:{
      ...semanticAttestation(),pinnedSha256:'d'.repeat(64),
    }}).disposition).toBe('CONFIG_IDENTITY_UNSCORABLE');
  });
  it('does not promote source-only or third-party normalized expected output',()=>{
    const capture={origin:'DEVICE_WIRE_CAPTURE_CLAIM' as const,
      configuration:sourceAttestation()};
    expect(judge({...capture,semanticExpected:{
      ...semanticAttestation(),origin:'LEXICAL_SOURCE_ONLY',
    }}).disposition).toBe('THIRD_PARTY_EXPECTATION_REVIEW_ONLY');
    expect(judge({...capture,semanticExpected:{
      ...semanticAttestation(),origin:'THIRD_PARTY_EXPECTED',
    }}).disposition).toBe('THIRD_PARTY_EXPECTATION_REVIEW_ONLY');
  });
  it('even complete *claimed* chain still requires external verification',()=>{
    const result=judge({origin:'DEVICE_WIRE_CAPTURE_CLAIM',
      configuration:sourceAttestation(),semanticExpected:semanticAttestation()});
    expect(result.disposition).toBe('DEVICE_EVIDENCE_EXTERNAL_REVIEW_ONLY');
    expect(result.formatCompatible).toBe(true);
    expect(result.sourceIdentityChecked).toBe(true);
    expect(result.canDecodeVendorEscapes).toBe(false);
    expect(result.canAutoPromote).toBe(false);
    expect(result.nativeTarget).toBe('NOT_VERIFIED');
  });
  it('requires RFC5424 SD structure, not merely the PRI+version prefix',()=>{
    const strict=encode('<165>1 2026-10-17T12:00:00Z host app - ID47 '+
      '[example@32473 a="v"]');
    const bogus=encode('<165>1 2026-13-17T12:00:00Z host app - ID47 '+
      '[example@32473 a="v"]');
    const forRfc=(raw:Uint8Array)=>judge({
      raw,pinnedSourceSha256:sha(raw),producer:'FORTIANALYZER',
      profile:'FORTIANALYZER_RFC5424',origin:'PINNED_REPO_FIXTURE',
      version:'7.2.6',configuration:null,semanticExpected:null,
    });
    expect(forRfc(strict).disposition).toBe('SOURCE_FIXTURE_NOT_DEVICE_PROOF');
    expect(forRfc(bogus).disposition).toBe('WIRE_SHAPE_CONFLICT');
    expect(forRfc(strict).canDecodeVendorEscapes).toBe(false);
  });
});
