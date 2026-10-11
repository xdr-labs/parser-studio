/** Read-only local pair inspection. Does not evaluate scripts or adopt imported rules. */
export interface PairInspectionRequest {
  name: string;
  confContent: string;
  fragmentContent: string;
}
export interface PairInspectionSummary {
  name: string;
  importStatus: 'EDITABLE_EXACT' | 'OPAQUE_READ_ONLY';
  editable: boolean;
  confSha256: string;
  fragmentSha256: string;
  protocols: Array<'udp' | 'tcp' | 'http'>;
  ports: number[];
  sourceCount: number;
  markersComplete: boolean;
  hasParseEntry: boolean;
  diagnostics: string[];
}
const BASE = '/api/v1/parser-pairs/inspect';
const LIMIT = 2 * 1024 * 1024;
const NAME = /^customized_[a-z][a-z0-9_]{1,47}$/;
const HEX = /^[a-f0-9]{64}$/;
const DIAGNOSTICS = new Set([
  'CONF_NO_SOURCE', 'CONF_UNSUPPORTED_PROTOCOL', 'CONF_INVALID_PORT',
  'CONF_SOURCE_MISMATCH', 'CONF_SOURCE_MISSING_REFERENCE',
  'CONF_RECEIVER_NOT_EDITABLE', 'CONF_MULTI_PORT_LAYOUT',
  'RUBY_MARKERS_INCOMPLETE', 'RUBY_PARSE_ENTRY_MISSING', 'PAIR_NOT_REPRODUCIBLE',
]);
async function sha256(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error('로컬 파일의 SHA-256 검증에는 안전한 브라우저 컨텍스트가 필요합니다.');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((part) => part.toString(16).padStart(2, '0')).join('');
}

export async function inspectParserPair(
  input: PairInspectionRequest,
  requester: typeof fetch = fetch,
): Promise<PairInspectionSummary> {
  if (!NAME.test(input.name) || !input.confContent || !input.fragmentContent) {
    throw new Error('두 파일은 customized_<slug> 및 customized_<slug>.conf 형식이어야 합니다.');
  }
  const body = JSON.stringify(input);
  if (new TextEncoder().encode(body).length > LIMIT) throw new Error('로컬 검사 입력은 합계 2 MiB 미만이어야 합니다.');
  const response = await requester(BASE, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body,
  });
  if (response.status !== 200) throw new Error('백엔드 검사 실패 (HTTP ' + response.status + '). 원본 파일은 저장되지 않았습니다.');
  let data: unknown;
  try { data = await response.json(); } catch {
    throw new Error('백엔드 검사 응답 형식이 잘못되었습니다.');
  }
  if (!data || typeof data !== 'object') throw new Error('검사 결과가 올바르지 않습니다.');
  const result = data as Record<string, unknown>;
  const hashes = result.originalHashes as Record<string, unknown> | undefined;
  const receiver = result.receiver as Record<string, unknown> | undefined;
  const fragment = result.fragment as Record<string, unknown> | undefined;
  const diagnostics = result.diagnostics as Array<Record<string, unknown>> | undefined;
  const exact = result.importStatus === 'EDITABLE_EXACT';
  if (result.format !== 'host-customized-pair' || result.name !== input.name ||
      !['EDITABLE_EXACT', 'OPAQUE_READ_ONLY'].includes(String(result.importStatus)) ||
      result.roundTripVerified !== exact ||
      (exact && (!result.portableProject || typeof result.portableProject !== 'object' ||
        (result.portableProject as { slug?: unknown }).slug !== input.name.replace(/^customized_/, '') ||
        (result.portableProject as { schemaRevision?: unknown }).schemaRevision !== '0.1')) ||
      (!exact && result.portableProject !== null) ||
      !hashes || !HEX.test(String(hashes.conf)) || !HEX.test(String(hashes.fragment)) ||
      !receiver || !Array.isArray(receiver.protocols) ||
      !receiver.protocols.every((p) => p === 'udp' || p === 'tcp' || p === 'http') ||
      !Array.isArray(receiver.ports) ||
      !receiver.ports.every((p) => Number.isInteger(p) && p >= 1 && p <= 65535) ||
      !Number.isInteger(receiver.sourceCount) || Number(receiver.sourceCount) < 0 ||
      !fragment || typeof fragment.markersComplete !== 'boolean' ||
      typeof fragment.hasParseEntry !== 'boolean' || typeof fragment.opaqueRuby !== 'boolean' ||
      !Array.isArray(diagnostics) || diagnostics.length > 64 ||
      !diagnostics.every((d) => DIAGNOSTICS.has(String(d.code)) && d.severity === 'warning')) {
    throw new Error('백엔드 검사 계약 또는 편집 가능 상태가 일치하지 않습니다.');
  }
  if (hashes.conf !== await sha256(input.confContent) ||
      hashes.fragment !== await sha256(input.fragmentContent)) {
    throw new Error('원본 파일의 SHA-256 검증 실패: 검사 결과를 표시하지 않습니다.');
  }
  // Never echo response messages or source fragments; expose only known codes.
  return {
    name: input.name, importStatus: exact ? 'EDITABLE_EXACT' : 'OPAQUE_READ_ONLY',
    editable: exact, confSha256: hashes.conf as string, fragmentSha256: hashes.fragment as string,
    protocols: receiver.protocols, ports: receiver.ports, sourceCount: receiver.sourceCount as number,
    markersComplete: fragment.markersComplete, hasParseEntry: fragment.hasParseEntry,
    diagnostics: diagnostics.map((d) => String(d.code)),
  };
}
