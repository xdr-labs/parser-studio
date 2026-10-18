import type { PairInspectionSummary } from './pairInspection';
import { reconstructExactBackendDraft } from './pairProjectImport';

/**
 * Safe and deterministic pair-import/loss review.
 *
 * Only whitelisted inspection codes and the verified SHA-256 digests are used.
 * The original Fluentd/Ruby files, raw events, vendor event values and any
 * executable code are never included in this report.
 */
export interface PairImportReview {
  contract: 'parser-studio.import-review.v0.1';
  pairName: string;
  source: {
    configSha256: string;
    rubySha256: string;
    receiverProtocols: Array<'udp'|'tcp'|'http'>;
    receiverPorts: number[];
    receiverCount: number;
  };
  classification: 'EXACT_BACKEND_PAIR' | 'OPAQUE_LEGACY_PAIR';
  backendByteReproducible: boolean;
  guidedImportAvailable: boolean;
  originalRubyExecutableByStudio: false;
  parserNativeVerified: false;
  sensorIngestVerified: false;
  targetImportVerified: false;
  lossAssessment: 'REQUIRES_MANUAL_REVIEW' | 'NO_IMPORT_PERFORMED';
  findings: Array<{ code: string; explanation: string }>;
  advice: string;
  rawFilesIncluded: false;
  rawLogsIncluded: false;
  credentialsIncluded: false;
}

const ALLOWED_DIAGNOSTICS: Record<string, string> = {
  CONF_NO_SOURCE: 'No supported Fluentd source was identified.',
  CONF_UNSUPPORTED_PROTOCOL: 'A receiver protocol is not supported by the current model.',
  CONF_INVALID_PORT: 'At least one source port is invalid or missing.',
  CONF_SOURCE_MISMATCH: 'CONF source tags or parser names do not match the pair.',
  CONF_SOURCE_MISSING_REFERENCE: 'A source is missing a parser reference or tag.',
  CONF_RECEIVER_NOT_EDITABLE: 'A receiver form cannot be edited by the Guided Builder.',
  CONF_MULTI_PORT_LAYOUT: 'Distinct source ports cannot be represented by one shared sensor/CONF port.',
  RUBY_MARKERS_INCOMPLETE: 'Required Ruby fragment section markers are incomplete.',
  RUBY_PARSE_ENTRY_MISSING: 'The recognized Ruby parse entry point is missing.',
  PAIR_NOT_REPRODUCIBLE: 'Exact byte reproduction from a supported backend project was not established.',
};
const PAIR=/^customized_[a-z][a-z0-9_]{1,47}$/;
const HASH=/^[a-f0-9]{64}$/;
const PROTOCOLS=new Set(['udp','tcp','http']);

export function buildPairImportReview(value: PairInspectionSummary): PairImportReview {
  if (!value || !PAIR.test(value.name) ||
      !HASH.test(value.confSha256) || !HASH.test(value.fragmentSha256) ||
      !Array.isArray(value.protocols) || value.protocols.length>3 ||
      value.protocols.some(p=>!PROTOCOLS.has(p)) ||
      new Set(value.protocols).size!==value.protocols.length ||
      !Array.isArray(value.ports) || value.ports.length>128 ||
      value.ports.some(p=>!Number.isInteger(p)||p<1||p>65535) ||
      new Set(value.ports).size!==value.ports.length ||
      !Number.isInteger(value.sourceCount) || value.sourceCount<0 || value.sourceCount>128 ||
      !Array.isArray(value.diagnostics) || value.diagnostics.length>64 ||
      value.diagnostics.some(code=>!Object.hasOwn(ALLOWED_DIAGNOSTICS,code)) ||
      typeof value.markersComplete!=='boolean' || typeof value.hasParseEntry!=='boolean' ||
      typeof value.editable!=='boolean' ||
      (value.editable && value.importStatus!=='EDITABLE_EXACT') ||
      (!value.editable && value.importStatus!=='OPAQUE_READ_ONLY')) {
    throw new Error('Parser import review requires validated metadata and matching SHA-256 hashes.');
  }
  const exact=value.editable;
  const restored=exact && value.portableProject!==undefined &&
    reconstructExactBackendDraft(value.portableProject,value.name)!==null;
  // No source code or untrusted backend diagnostic messages are reflected.
  const findings=[...new Set(value.diagnostics)].map(code=>({
    code,explanation:ALLOWED_DIAGNOSTICS[code],
  }));
  return {
    contract:'parser-studio.import-review.v0.1',
    pairName:value.name,
    source:{
      configSha256:value.confSha256,
      rubySha256:value.fragmentSha256,
      receiverProtocols:[...value.protocols],
      receiverPorts:[...value.ports],
      receiverCount:value.sourceCount,
    },
    classification:exact?'EXACT_BACKEND_PAIR':'OPAQUE_LEGACY_PAIR',
    backendByteReproducible:exact,
    guidedImportAvailable:restored,
    originalRubyExecutableByStudio:false,
    parserNativeVerified:false,
    sensorIngestVerified:false,
    targetImportVerified:false,
    lossAssessment:exact?'NO_IMPORT_PERFORMED':'REQUIRES_MANUAL_REVIEW',
    findings,
    advice:restored
      ? 'The backend verified both files as byte-reproducible, and their complete project can be reconstructed without a lossy mapping. Restoring into a draft requires separate explicit confirmation, clears raw samples and does not save automatically. Native parsing and target import remain unverified.'
      : exact
      ? 'The backend identified a byte-reproducible pair, but its project does not round-trip into the current Guided Builder. No import or native/target verification is performed.'
      : 'This legacy pair is opaque. Field mappings, conversions and control flow cannot be safely reconstructed or assessed for loss from structural inspection alone. Retain the original files and review them independently; no automatic import is available.',
    rawFilesIncluded:false,
    rawLogsIncluded:false,
    credentialsIncluded:false,
  };
}
