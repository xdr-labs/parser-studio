import {describe,expect,it} from 'vitest';
import {reviewFortiAnalyzerRelayFidelity,type FortiAnalyzerRelayConfig}
  from './fortianalyzerRelayFidelityGate';

const pure:FortiAnalyzerRelayConfig={
  producer:'FORTIANALYZER',
  deviceVersion:'7.6.6',
  configOrigin:'DEVICE_CONFIGURATION_EXPORT_CLAIM',
  forwarding:'forwarding',
  serverType:'syslog',wireFormat:'fgt',transparent:'enable',
  masking:'disable',fieldExclusion:'disable',
  decodeBase64:'disable',enrichCve:'disable',
  sourceIp:'original_ip',
};
const review=(changes:Partial<FortiAnalyzerRelayConfig>={})=>
  reviewFortiAnalyzerRelayFidelity({...pure,...changes});
describe('FortiAnalyzer 7.6.6 forwarding-stage lossless source gate',()=>{
  it('keeps even nominally transparent, unmasked syslog in collector-only review',()=>{
    const result=review();
    expect(result.disposition).toBe('TRANSPARENT_CLAIM_UNATTESTED');
    expect(result.effects).toEqual(['TRANSPARENCY_NOT_ATTESTED']);
    expect(result.payloadFidelity).toBe('TRANSPARENT_CONFIG_UNATTESTED');
    expect(result.originalDeviceByteEquivalence).toBe('NOT_PROVEN');
    expect(result.collectorInputOnly).toBe(true);
    expect(result.canAutoPromote).toBe(false);
  });
  it('separates source IP rewrite from actual payload transformation',()=>{
    const r=review({sourceIp:'local_ip'});
    expect(r.effects).toEqual(['ORIGIN_IP_REWRITTEN','TRANSPARENCY_NOT_ATTESTED']);
    expect(r.payloadFidelity).toBe('TRANSPARENT_CONFIG_UNATTESTED');
    expect(r.originalDeviceByteEquivalence).toBe('NOT_PROVEN');
  });
  it('distinguishes explicit FortiAnalyzer syslog wrapping from FGT passthrough',()=>{
    const wrapped=review({transparent:'disable'});
    expect(wrapped.disposition).toBe('PAYLOAD_TRANSFORMED_REVIEW_ONLY');
    expect(wrapped.effects).toContain('FORTIANALYZER_SYSLOG_WRAPPER');
    expect(wrapped.payloadFidelity).toBe('POTENTIALLY_TRANSFORMED');
    expect(wrapped.canAutoPromote).toBe(false);
  });
  it('distinguishes append-only FortiAnalyzer enrichment',()=>{
    const r=review({transparent:'faz-enrich',wireFormat:'rfc-5424'});
    expect(r.effects).toContain('FORTIANALYZER_FIELDS_ENRICHED');
    expect(r.payloadFidelity).toBe('POTENTIALLY_TRANSFORMED');
    expect(r.vendorEscapeSemantics).toBe('NOT_CERTIFIED');
  });
  it('reports masking/exclusions independently of transparent forwarding setting',()=>{
    for(const changes of [
      {masking:'enable'} as const,{fieldExclusion:'enable'} as const,
      {masking:'enable',fieldExclusion:'enable'} as const,
    ]){
      const r=review(changes);
      expect(r.disposition).toBe('PAYLOAD_TRANSFORMED_REVIEW_ONLY');
      expect(r.payloadFidelity).toBe('POTENTIALLY_TRANSFORMED');
      expect(r.originalDeviceByteEquivalence).toBe('NOT_PROVEN');
      expect(r.canAutoPromote).toBe(false);
    }
    expect(review({masking:'enable',fieldExclusion:'enable'}).effects)
      .toEqual(['FIELDS_MASKED','FIELDS_EXCLUDED']);
  });
  it('separates IPS attackcontext base64 and CVE field transformations',()=>{
    const r=review({decodeBase64:'enable',enrichCve:'enable'});
    expect(r.effects).toEqual(['ATTACKCONTEXT_BASE64_DECODED','CVE_FIELD_ENRICHED']);
    expect(r.disposition).toBe('PAYLOAD_TRANSFORMED_REVIEW_ONLY');
    expect(r.canAutoPromote).toBe(false);
  });
  it('treats FortiAnalyzer CEF destination as a distinct output, not FGT syslog',()=>{
    const cef=review({
      serverType:'cef',wireFormat:null,transparent:null,
      decodeBase64:null,enrichCve:null,
    });
    expect(cef.disposition).toBe('PAYLOAD_TRANSFORMED_REVIEW_ONLY');
    expect(cef.effects).toEqual(['REENCODED_CEF']);
    expect(cef.payloadFidelity).toBe('POTENTIALLY_TRANSFORMED');
    expect(cef.vendorEscapeSemantics).toBe('NOT_CERTIFIED');
  });
  it('rejects CEF with a wrongly borrowed syslog-format selector or enrich setting',()=>{
    expect(review({serverType:'cef'}).disposition)
      .toBe('INCOMPLETE_OR_CONFLICTING_CONFIGURATION');
    expect(review({
      serverType:'cef',wireFormat:null,transparent:null,
      decodeBase64:'enable',enrichCve:null,
    }).disposition).toBe('INCOMPLETE_OR_CONFLICTING_CONFIGURATION');
  });
  it('never infers omitted config options from advertised CLI defaults',()=>{
    for(const change of [
      {transparent:null}, {masking:null}, {fieldExclusion:null},
      {decodeBase64:null}, {enrichCve:null}, {sourceIp:null},
      {wireFormat:null},
    ] as const){
      const verdict=review(change);
      expect(verdict.disposition).toBe('INCOMPLETE_OR_CONFLICTING_CONFIGURATION');
      expect(verdict.payloadFidelity).toBe('UNKNOWN');
      expect(verdict.canAutoPromote).toBe(false);
    }
  });
  it('refuses untrusted documentation snippets or a declared firmware number',()=>{
    for(const configOrigin of [
      'VENDOR_DOCUMENTATION','USER_DECLARED','REPOSITORY_FIXTURE',
    ] as const){
      const verdict=review({configOrigin,transparent:'enable'});
      expect(verdict.disposition).toBe('UNVERIFIED_CONFIGURATION_ORIGIN');
      expect(verdict.originalDeviceByteEquivalence).toBe('NOT_PROVEN');
    }
  });
  it('is specifically pinned to documented version, not guessed later firmware',()=>{
    for(const deviceVersion of ['7.2.6','7.4.8','7.6.5','7.6.7','8.0.0',null]){
      const verdict=review({deviceVersion});
      expect(verdict.disposition).toBe('VERSION_NOT_DOCUMENTED');
      expect(verdict.documentedForVersion).toBe('NOT_DOCUMENTED');
    }
  });
  it('refuses unsupported modes, missing destination, and aggregation-only config',()=>{
    for(const update of [
      {forwarding:'disable'},{forwarding:'aggregation'},{forwarding:null},
    ] as const)expect(review(update).disposition).toBe('FORWARDING_STATE_UNSCORABLE');
    expect(review({serverType:null}).disposition).toBe('UNSUPPORTED_DESTINATION');
    expect(review({serverType:'other'}).disposition).toBe('UNSUPPORTED_DESTINATION');
  });
});
