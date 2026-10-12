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
  if (response.status !== 200) throw new Error('기능 확인 API가 응답하지 않습니다 (HTTP ' + response.status + ').');
  let value: unknown;
  try { value = await response.json(); } catch {
    throw new Error('기능 확인 API가 올바른 JSON을 반환하지 않았습니다.');
  }
  if (!value || typeof value !== 'object') throw new Error('백엔드 기능 계약이 없습니다.');
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
    throw new Error('백엔드 기능·검증 상태를 신뢰할 수 없어 DRAFT 생성을 차단했습니다.');
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
  )) throw new Error('확장 RFC5424/LEEF 기능 선언이 현재 검토한 계약과 다릅니다.');
  return cap as BackendCapabilities;
}

export function assertBackendProjectSupported(project: BackendParserProject, cap: BackendCapabilities): void {
  if (project.extraction.format === 'syslog_rfc5424') {
    const mode = project.extraction.syslogBodyFormat ?? 'raw';
    if ((cap.authoring.rfc5424BodyFormats && !cap.authoring.rfc5424BodyFormats.includes(mode)) ||
        (['cef', 'leef'].includes(mode) &&
          !cap.authoring.rfc5424BodyFormats?.includes(mode as 'cef' | 'leef'))) {
      throw new Error('백엔드가 RFC5424 내부 ' + mode.toUpperCase() + ' 추출 형식을 명시적으로 지원하지 않습니다.');
    }
  }
  if (!cap.authoring.extractionFormats.includes(project.extraction.format)) {
    throw new Error('백엔드가 ' + project.extraction.format.toUpperCase() + ' 포맷을 지원한다고 확인하지 않았습니다.');
  }
  if (!project.receiver.protocols.every((protocol) => cap.authoring.receiverProtocols.includes(protocol))) {
    throw new Error('백엔드가 선택한 UDP/TCP 수신 방식을 지원하지 않습니다.');
  }
  if (new TextEncoder().encode(JSON.stringify(project)).length > cap.limits.maxProjectBodyBytes) {
    throw new Error('백엔드 프로젝트 크기 제한을 초과했습니다.');
  }
}
