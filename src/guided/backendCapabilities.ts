import type { BackendParserProject } from './backendAdapter';

/** A private loopback API advertises supported authoring features, not deployment approval. */
export interface BackendCapabilities {
  contract: 'host-customized-pair.v0.1';
  projectSchemaRevision: '0.1';
  authoring: {
    receiverProtocols: Array<'udp' | 'tcp'>;
    extractionFormats: Array<'json' | 'kv' | 'csv' | 'syslog_rfc5424' | 'cef' | 'leef'>;
    formatCoverage: 'reviewed-bounded-subset';
    /** Only advertised by backend revisions implementing bounded nested bodies/SD. */
    rfc5424BodyFormats?: Array<'raw' | 'json' | 'kv' | 'cef' | 'leef'>;
    rfc5424AdjacentStructuredDataSubset?: true;
    rfc5424StructuredDataMaxBytes?: 1024;
    leefHexSeparatorSubset?: true;
    httpReceiver: false;
    multipleDistinctReceiverPorts: false;
    multiline: false;
    arbitraryRuby: false;
  };
  /** Optional gated synthetic-only backend preview capabilities. Not sensor readiness. */
  testLab?: {
    offlineJsonPreview?: boolean;
    requiresBackendPreviewAuthorization?: boolean;
    liveSensorSenderEnabled?: boolean;
    trustedSinkSessionControlAvailable?: boolean;
    sessionControlRequiresBackendAuthorization?: boolean;
    sessionMaxRatePerSecond?: number;
    sessionMaxLeaseMs?: number;
    sessionMaxAdditionalEventsPerRenewal?: number;
    sessionMaxCumulativeEvents?: number;
    sessionRenewalRequiresSeparateApproval?: boolean;
    sessionDurableAcrossRestart?: boolean;
    serverInjectedUdpTcpSinkAvailable?: boolean;
    sinkRequiresIpLiteralAllowlist?: boolean;
    sinkRequiresPerDeliveryPolicyAndAudit?: boolean;
    sensorIngestVerified?: boolean;
    runtimeParsingVerified?: boolean;
  };
  downloads?: {
    individualGeneratedFiles: true;
    zipWithManifest: true;
    requiresDpConnection: false;
    requiresApiKey: false;
    autoDeploys: false;
    exactArtifactRevision: true;
  };
  import: {
    exactInternalPairsEditable: true;
    unknownLegacyRubyEditable: false;
    structuralInspectionOnly: true;
  };
  verification: {
    engineVerified: false;
    targetImportVerified: false;
    liveListenerVerified: false;
    proprietaryLoaderVerified: false;
  };
  limits: { maxProjectBodyBytes: number; maxInspectBodyBytes: number };
}

const BASE = '/api/v1/parser-pairs';
const KNOWN_FORMATS = new Set(['json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef']);
const KNOWN_PROTOCOLS = new Set(['udp', 'tcp']);
const KNOWN_RFC_BODIES = new Set(['raw','json','kv','cef','leef']);

export async function fetchBackendCapabilities(
  requester: typeof fetch = fetch,
): Promise<BackendCapabilities> {
  const response = await requester(BASE + '/capabilities', {
    method: 'GET',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });
  if (response.status !== 200) throw new Error('Backend capabilities request failed (HTTP ' + response.status + ').');
  let value: unknown;
  try { value = await response.json(); } catch {
    throw new Error('The capabilities API returned invalid JSON.');
  }
  if (!value || typeof value !== 'object') throw new Error('Backend capability contract is missing.');
  const cap = value as Partial<BackendCapabilities>;
  const a = cap.authoring;
  const im = cap.import;
  const v = cap.verification;
  const l = cap.limits;
  if (cap.contract !== 'host-customized-pair.v0.1' ||
      cap.projectSchemaRevision !== '0.1' ||
      !a || !Array.isArray(a.extractionFormats) || a.extractionFormats.length === 0 ||
      new Set(a.extractionFormats).size !== a.extractionFormats.length ||
      !a.extractionFormats.every((format) => KNOWN_FORMATS.has(format)) ||
      !Array.isArray(a.receiverProtocols) || a.receiverProtocols.length === 0 ||
      new Set(a.receiverProtocols).size !== a.receiverProtocols.length ||
      !a.receiverProtocols.every((p) => KNOWN_PROTOCOLS.has(p)) ||
      a.formatCoverage !== 'reviewed-bounded-subset' ||
      a.httpReceiver !== false || a.multipleDistinctReceiverPorts !== false ||
      a.multiline !== false || a.arbitraryRuby !== false ||
      im?.exactInternalPairsEditable !== true ||
      im.unknownLegacyRubyEditable !== false || im.structuralInspectionOnly !== true ||
      v?.engineVerified !== false || v.targetImportVerified !== false ||
      v.liveListenerVerified !== false || v.proprietaryLoaderVerified !== false ||
      !Number.isInteger(l?.maxProjectBodyBytes) || !Number.isInteger(l?.maxInspectBodyBytes) ||
      (l?.maxProjectBodyBytes ?? 0) < 1024 || (l?.maxInspectBodyBytes ?? 0) < 1024) {
    throw new Error('DRAFT generation blocked due to untrusted backend capabilities or verification flags.');
  }
  const extended = a.rfc5424BodyFormats !== undefined ||
    a.rfc5424AdjacentStructuredDataSubset !== undefined ||
    a.rfc5424StructuredDataMaxBytes !== undefined ||
    a.leefHexSeparatorSubset !== undefined;
  if (extended && (
    !Array.isArray(a.rfc5424BodyFormats) ||
    a.rfc5424BodyFormats.length < 3 ||
    a.rfc5424BodyFormats.length > KNOWN_RFC_BODIES.size ||
    new Set(a.rfc5424BodyFormats).size !== a.rfc5424BodyFormats.length ||
    !a.rfc5424BodyFormats.every((mode) => KNOWN_RFC_BODIES.has(mode)) ||
    a.rfc5424AdjacentStructuredDataSubset !== true ||
    a.rfc5424StructuredDataMaxBytes !== 1024 ||
    a.leefHexSeparatorSubset !== true
  )) throw new Error('Extended RFC5424/LEEF capability declarations do not match the reviewed contract.');
  if (cap.downloads !== undefined) {
    const dl = cap.downloads;
    if (!dl || typeof dl !== 'object' ||
        Object.keys(dl).sort().join(',') !==
          'autoDeploys,exactArtifactRevision,individualGeneratedFiles,requiresApiKey,requiresDpConnection,zipWithManifest' ||
        dl.individualGeneratedFiles !== true || dl.zipWithManifest !== true ||
        dl.requiresDpConnection !== false || dl.requiresApiKey !== false ||
        dl.autoDeploys !== false || dl.exactArtifactRevision !== true) {
      throw new Error('Backend ZIP download capabilities do not match the reviewed contract.');
    }
  }
  return cap as BackendCapabilities;
}

export function assertBackendProjectSupported(project: BackendParserProject, cap: BackendCapabilities): void {
  if (project.extraction.format === 'syslog_rfc5424') {
    const mode = project.extraction.syslogBodyFormat ?? 'raw';
    if ((cap.authoring.rfc5424BodyFormats && !cap.authoring.rfc5424BodyFormats.includes(mode)) ||
        (['cef', 'leef'].includes(mode) &&
          !cap.authoring.rfc5424BodyFormats?.includes(mode as 'cef' | 'leef'))) {
      throw new Error('Backend does not explicitly support RFC5424-embedded ' + mode.toUpperCase() + ' extraction.');
    }
  }
  if (!cap.authoring.extractionFormats.includes(project.extraction.format)) {
    throw new Error('Backend did not confirm support for ' + project.extraction.format.toUpperCase() + ' format.');
  }
  if (!project.receiver.protocols.every((protocol) => cap.authoring.receiverProtocols.includes(protocol))) {
    throw new Error('Backend does not support the selected UDP/TCP receiver protocol.');
  }
  if (new TextEncoder().encode(JSON.stringify(project)).length > cap.limits.maxProjectBodyBytes) {
    throw new Error('Backend project size limit exceeded.');
  }
}
