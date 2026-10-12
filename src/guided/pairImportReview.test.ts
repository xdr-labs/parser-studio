import { describe, expect, it } from 'vitest';
import type { PairInspectionSummary } from './pairInspection';
import { buildPairImportReview } from './pairImportReview';

const opaque:PairInspectionSummary = {
  name:'customized_example_fw',importStatus:'OPAQUE_READ_ONLY',editable:false,
  confSha256:'1'.repeat(64),fragmentSha256:'a'.repeat(64),
  protocols:['udp'],ports:[6800],sourceCount:1,
  markersComplete:false,hasParseEntry:false,
  diagnostics:['PAIR_NOT_REPRODUCIBLE','RUBY_PARSE_ENTRY_MISSING'],
};

describe('safe import compatibility and loss-risk assessment',()=>{
  it('does not misrepresent opaque legacy Ruby as importable, lossless, or verified',()=>{
    const report=buildPairImportReview(opaque);
    expect(report).toMatchObject({
      contract:'parser-studio.import-review.v0.1',
      classification:'OPAQUE_LEGACY_PAIR',
      backendByteReproducible:false,guidedImportAvailable:false,
      originalRubyExecutableByStudio:false,
      parserNativeVerified:false,sensorIngestVerified:false,targetImportVerified:false,
      lossAssessment:'REQUIRES_MANUAL_REVIEW',
      source:{configSha256:opaque.confSha256,rubySha256:opaque.fragmentSha256,
        receiverPorts:[6800],receiverProtocols:['udp'],receiverCount:1},
      rawFilesIncluded:false,rawLogsIncluded:false,credentialsIncluded:false,
    });
    expect(report.findings.map(x=>x.code)).toEqual([
      'PAIR_NOT_REPRODUCIBLE','RUBY_PARSE_ENTRY_MISSING',
    ]);
    expect(report.advice).toContain('cannot be safely reconstructed');
    expect(JSON.stringify(report)).not.toContain('STELLAR_PARSE_BEGIN');
  });
  it('reports exact byte reproduction, but never promises direct Guided editing or target E2E',()=>{
    const exact:PairInspectionSummary={
      ...opaque,editable:true,importStatus:'EDITABLE_EXACT',
      markersComplete:true,hasParseEntry:true,diagnostics:[],
    };
    const report=buildPairImportReview(exact);
    expect(report.classification).toBe('EXACT_BACKEND_PAIR');
    expect(report.lossAssessment).toBe('NO_IMPORT_PERFORMED');
    expect(report.backendByteReproducible).toBe(true);
    expect(report.guidedImportAvailable).toBe(false);
    expect(report.parserNativeVerified).toBe(false);
    expect(report.advice).toContain('No import');
  });
  it('records explicit restoration availability only when an exact project truly reverses',()=>{
    // A forged editable status without a proven convertible project is NOT enough.
    const reported={...opaque,editable:true as const,
      importStatus:'EDITABLE_EXACT' as const,diagnostics:[]};
    expect(buildPairImportReview(reported).guidedImportAvailable).toBe(false);
    // The complete, exactly round-tripping case is covered by pairProjectImport.
  });
  it('exports fixed diagnostics, not potentially sensitive backend error messages',()=>{
    const report=buildPairImportReview({...opaque,
      diagnostics:['CONF_SOURCE_MISMATCH','CONF_MULTI_PORT_LAYOUT','CONF_SOURCE_MISMATCH'],
      protocols:['udp','tcp'],ports:[6800,6801],sourceCount:2,
    });
    expect(report.findings).toHaveLength(2);
    expect(report.findings.map(x=>x.code)).toEqual([
      'CONF_SOURCE_MISMATCH','CONF_MULTI_PORT_LAYOUT',
    ]);
    expect(report.findings[1]?.explanation).toContain('one shared sensor/CONF port');
    expect(JSON.stringify(report)).not.toMatch(/api_key|PRIVATE_JWT|rawEvent|secret/i);
  });
  it.each([
    {...opaque,name:'../secret'},
    {...opaque,confSha256:'bad'},
    {...opaque,fragmentSha256:'0'.repeat(62)},
    {...opaque,ports:[0]},
    {...opaque,ports:[6800,6800]},
    {...opaque,protocols:['http','smtp']},
    {...opaque,sourceCount:-1},
    {...opaque,diagnostics:['UNTRUSTED_PRIVATE_ERROR']},
    {...opaque,editable:true},
    {...opaque,importStatus:'EDITABLE_EXACT'},
  ] as PairInspectionSummary[])('fails closed on inconsistent or unsafe inspection metadata',broken=>{
    expect(()=>buildPairImportReview(broken)).toThrow();
  });
});
