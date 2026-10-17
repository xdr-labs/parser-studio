/** Isolated documentary/configuration/wire evidence adjudication.
 * A source SHA, document, declared firmware or fixture filename never certifies
 * manufacture-specific escape semantics. All results are evidence-only.
 */
import {createHash} from 'node:crypto';
import {observedWireShape,type ObservedShape} from './transportEscapeReview';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';

export type Producer='FORTIGATE'|'FORTIANALYZER'|'SONICWALL'|'SOPHOS_FIREWALL';
export type WireProfile='FORTIGATE_FGT'|'FORTIGATE_CEF'|
  'FORTIANALYZER_FGT'|'FORTIANALYZER_RFC5424'|
  'SONICOS_DEFAULT'|'SONICOS_ENHANCED'|'SONICOS_CEF'|
  'SOPHOS_STANDARD'|'SOPHOS_LEGACY';
export type EvidenceOrigin='PINNED_REPO_FIXTURE'|'MANUFACTURER_DOCUMENT'|
  'DEVICE_WIRE_CAPTURE_CLAIM';
export type ConfigOrigin='INFERRED_FROM_FILENAME'|'USER_DECLARED'|
  'DEVICE_CONFIGURATION_EXPORT_CLAIM';
export type SemanticOrigin='LEXICAL_SOURCE_ONLY'|'THIRD_PARTY_EXPECTED'|
  'DEVICE_WIRE_EXPECTED_CLAIM';
export type EvidenceDisposition=
  'SOURCE_IDENTITY_UNSCORABLE'|'SOURCE_UTF8_UNSCORABLE'|
  'PRODUCER_FORMAT_CONFLICT'|'WIRE_SHAPE_CONFLICT'|
  'SOURCE_FIXTURE_NOT_DEVICE_PROOF'|'CONFIG_PROOF_MISSING'|
  'CONFIG_IDENTITY_UNSCORABLE'|'SEMANTIC_EXPECTATION_MISSING'|
  'THIRD_PARTY_EXPECTATION_REVIEW_ONLY'|'DEVICE_EVIDENCE_EXTERNAL_REVIEW_ONLY';
export type ProvenanceInput={
  raw:Uint8Array;
  pinnedSourceSha256:string;
  producer:Producer;
  profile:WireProfile;
  origin:EvidenceOrigin;
  version:string|null;
  configuration:{
    origin:ConfigOrigin;
    bytes:Uint8Array;
    pinnedSha256:string;
    originalSourceSha256:string;
  }|null;
  semanticExpected:{
    origin:SemanticOrigin;
    expectedBytes:Uint8Array;
    pinnedSha256:string;
    originalSourceSha256:string;
  }|null;
};
export type ProvenanceDecision={
  disposition:EvidenceDisposition;
  observed:ObservedShape;
  sourceIdentityChecked:boolean;
  formatCompatible:boolean;
  versionRisk:'FORTIANALYZER_7_2_6_ESCAPE_CHANGE'|'VERSION_NOT_VERIFIED';
  manufacturerSemantics:'NOT_CERTIFIED';
  nativeTarget:'NOT_VERIFIED';
  canDecodeVendorEscapes:false;
  canAutoPromote:false;
};
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const sha256=/^[a-f0-9]{64}$/;
const pair:Record<WireProfile,Producer>={
  FORTIGATE_FGT:'FORTIGATE',FORTIGATE_CEF:'FORTIGATE',
  FORTIANALYZER_FGT:'FORTIANALYZER',
  FORTIANALYZER_RFC5424:'FORTIANALYZER',
  SONICOS_DEFAULT:'SONICWALL',SONICOS_ENHANCED:'SONICWALL',SONICOS_CEF:'SONICWALL',
  SOPHOS_STANDARD:'SOPHOS_FIREWALL',SOPHOS_LEGACY:'SOPHOS_FIREWALL',
};
const expectedShape:Record<WireProfile,ObservedShape>={
  FORTIGATE_FGT:'KV_LEXICAL',FORTIGATE_CEF:'CEF_HEADER',
  FORTIANALYZER_FGT:'KV_LEXICAL',FORTIANALYZER_RFC5424:'RFC5424_HEADER',
  SONICOS_DEFAULT:'KV_LEXICAL',SONICOS_ENHANCED:'KV_LEXICAL',
  SONICOS_CEF:'CEF_HEADER',
  SOPHOS_STANDARD:'KV_LEXICAL',SOPHOS_LEGACY:'KV_LEXICAL',
};
const decoder=new TextDecoder('utf-8',{fatal:true});
export function judgeVendorEscapeProvenance(input:ProvenanceInput):ProvenanceDecision{
  const risk=(()=>{
    if(input.producer!=='FORTIANALYZER')return 'VERSION_NOT_VERIFIED' as const;
    const match=/^7\.2\.([0-9]+)$/.exec(input.version??'');
    return match&&Number(match[1])>=6?
      'FORTIANALYZER_7_2_6_ESCAPE_CHANGE' as const:'VERSION_NOT_VERIFIED' as const;
  })();
  let observed:ObservedShape='OTHER';
  const result=(disposition:EvidenceDisposition,sourceIdentityChecked=false,
    formatCompatible=false):ProvenanceDecision=>({
    disposition,observed,sourceIdentityChecked,formatCompatible,versionRisk:risk,
    manufacturerSemantics:'NOT_CERTIFIED',nativeTarget:'NOT_VERIFIED',
    canDecodeVendorEscapes:false,canAutoPromote:false,
  });
  // The exact raw octets, not a lossy JS string, establish source identity.
  if(input.raw.length===0||input.raw.length>16384||
    !sha256.test(input.pinnedSourceSha256)||
    hash(input.raw)!==input.pinnedSourceSha256)
    return result('SOURCE_IDENTITY_UNSCORABLE');
  let raw:string;
  try{raw=decoder.decode(input.raw);}catch{return result('SOURCE_UTF8_UNSCORABLE',true);}
  observed=observedWireShape(raw);
  if(pair[input.profile]!==input.producer)
    return result('PRODUCER_FORMAT_CONFLICT',true);
  if(observed!==expectedShape[input.profile]||
    (input.profile==='FORTIANALYZER_RFC5424'&&
      rfc5424SdByteEscapes(input.raw)===null))
    return result('WIRE_SHAPE_CONFLICT',true);
  if(input.origin!=='DEVICE_WIRE_CAPTURE_CLAIM')
    return result('SOURCE_FIXTURE_NOT_DEVICE_PROOF',true,true);
  if(!input.configuration||!input.version||!/^\d+\.\d+(?:\.\d+){0,2}$/.test(input.version))
    return result('CONFIG_PROOF_MISSING',true,true);
  if(input.configuration.origin!=='DEVICE_CONFIGURATION_EXPORT_CLAIM'||
    !sha256.test(input.configuration.pinnedSha256)||
    hash(input.configuration.bytes)!==input.configuration.pinnedSha256||
    input.configuration.originalSourceSha256!==input.pinnedSourceSha256)
    return result('CONFIG_IDENTITY_UNSCORABLE',true,true);
  if(!input.semanticExpected)
    return result('SEMANTIC_EXPECTATION_MISSING',true,true);
  if(!sha256.test(input.semanticExpected.pinnedSha256)||
     hash(input.semanticExpected.expectedBytes)!==input.semanticExpected.pinnedSha256||
     input.semanticExpected.originalSourceSha256!==input.pinnedSourceSha256)
    return result('CONFIG_IDENTITY_UNSCORABLE',true,true);
  if(input.semanticExpected.origin!=='DEVICE_WIRE_EXPECTED_CLAIM')
    return result('THIRD_PARTY_EXPECTATION_REVIEW_ONLY',true,true);
  // Byte integrity is checked, but origin labels and firmware/format declarations
  // still need independent external attestation. Nothing is certified in code.
  return result('DEVICE_EVIDENCE_EXTERNAL_REVIEW_ONLY',true,true);
}
