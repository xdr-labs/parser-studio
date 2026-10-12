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
  if (!globalThis.crypto?.subtle) throw new Error('SHA-256 verification of local files requires a secure browser context.');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((part) => part.toString(16).padStart(2, '0')).join('');
}

export async function inspectParserPair(
  input: PairInspectionRequest,
  requester: typeof fetch = fetch,
): Promise<PairInspectionSummary> {
  if (!NAME.test(input.name) || !input.confContent || !input.fragmentContent) {
    throw new Error('Files must be named customized_<slug> and customized_<slug>.conf.');
  }
  const body = JSON.stringify(input);
  if (new TextEncoder().encode(body).length > LIMIT) throw new Error('Local inspection input must total less than 2 MiB.');
  const response = await requester(BASE, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body,
  });
  if (response.status !== 200) throw new Error('Backend inspection failed (HTTP ' + response.status + '). Raw files were not stored.');
  let data: unknown;
  try { data = await response.json(); } catch {
    throw new Error('Invalid backend inspection response format.');
  }
  if (!data || typeof data !== 'object') throw new Error('Invalid inspection results.');
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
    throw new Error('Backend inspection contract or editable status is inconsistent.');
  }
  if (hashes.conf !== await sha256(input.confContent) ||
      hashes.fragment !== await sha256(input.fragmentContent)) {
    throw new Error('Original-file SHA-256 verification failed; results are not displayed.');
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
