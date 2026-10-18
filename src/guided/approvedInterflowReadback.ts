import type { BackendCapabilities } from './backendCapabilities';

/**
 * An explicitly requested, owner-authenticated Interflow field comparison.
 * Neither a browser DP client nor a sensor transport. The backend exclusively
 * owns tenant identity, data-read grants, audit logging and the vendor JWT.
 * The returned status is deliberately NOT proof of native or end-to-end success.
 */
export type InterflowIndex = 'session' | 'threat' | 'syslog' | 'winlogevent';
export type FieldComparisonStatus = 'MATCH' | 'MISMATCH' | 'MISSING';
export interface InterflowReadbackRequest {
  runId: string;
  index: InterflowIndex;
  markerField: string;
  expectedField: string;
  expectedValue: string;
  lookbackMinutes: 1 | 5 | 10;
}
export interface InterflowReadbackResult {
  state: 'MATCHED_RESPONSE_FIELDS' | 'FIELD_MISMATCH' | 'NO_MATCH';
  matchCount: number;
  fields: Array<{ field: string; status: FieldComparisonStatus }>;
  sensorReceivedVerified: false;
  endToEndVerified: false;
  runtimeParsingVerified: false;
  targetImportVerified: false;
}

const RUN = /^test_run_[0-9a-f]{32}$/;
const FIELD = /^[A-Za-z_][A-Za-z0-9_.-]{0,95}$/;
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const INDEXES = new Set(['session', 'threat', 'syslog', 'winlogevent']);
const VALUES = /^[\x20-\x7E]{1,128}$/;
const RESULT_KEYS = [
  'state','matchCount','fields','sensorReceivedVerified','endToEndVerified',
  'runtimeParsingVerified','targetImportVerified',
].sort().join(',');
const FIELD_KEYS = 'field,status';

function fieldName(value: unknown): value is string {
  return typeof value === 'string' && FIELD.test(value) &&
    value.split('.').every(part => Boolean(part) && !FORBIDDEN.has(part));
}

export function assertInterflowReadbackCapability(cap: BackendCapabilities): void {
  const t = cap?.testLab;
  if (!t ||
    t.interflowReadClientAvailable !== true ||
    t.interflowBoundedPollingAvailable !== true ||
    t.interflowMaxPollAttempts !== 6 ||
    t.interflowMaxPollWindowMs !== 15000 ||
    t.interflowCursorVerified !== false ||
    t.interflowSearchPermissionsVerified !== false ||
    t.interflowRealTargetVerified !== false ||
    t.sensorIngestVerified !== false ||
    t.runtimeParsingVerified !== false) {
    throw new Error('The backend does not advertise the reviewed, separately audited Interflow readback contract.');
  }
}

export function validateInterflowReadback(
  value: unknown, expectedField: string, limit: number,
): InterflowReadbackResult {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== RESULT_KEYS) {
    throw new Error('Interflow returned untrusted or unexpected response fields.');
  }
  const result = value as Partial<InterflowReadbackResult>;
  if (!['MATCHED_RESPONSE_FIELDS', 'FIELD_MISMATCH', 'NO_MATCH'].includes(String(result.state)) ||
    !Number.isInteger(result.matchCount) || (result.matchCount ?? -1) < 0 ||
    (result.matchCount ?? Number.MAX_SAFE_INTEGER) > limit ||
    result.sensorReceivedVerified !== false ||
    result.endToEndVerified !== false ||
    result.runtimeParsingVerified !== false ||
    result.targetImportVerified !== false ||
    !Array.isArray(result.fields) || result.fields.length !== 1) {
    throw new Error('Interflow response failed the non-verification or result-limit checks.');
  }
  const field = result.fields[0];
  if (!field || typeof field !== 'object' || Array.isArray(field) ||
    Object.keys(field).sort().join(',') !== FIELD_KEYS ||
    field.field !== expectedField ||
    !['MATCH', 'MISMATCH', 'MISSING'].includes(String(field.status))) {
    throw new Error('Interflow returned an unrequested field or sensitive comparison data.');
  }
  if (
    (result.state === 'NO_MATCH' && (result.matchCount !== 0 || field.status !== 'MISSING')) ||
    (result.state === 'MATCHED_RESPONSE_FIELDS' &&
      (result.matchCount === 0 || field.status !== 'MATCH')) ||
    (result.state === 'FIELD_MISMATCH' &&
      (result.matchCount === 0 || field.status === 'MATCH'))
  ) {
    throw new Error('Interflow result state conflicts with the field comparison evidence.');
  }
  return result as InterflowReadbackResult;
}

export async function queryApprovedInterflowReadback(
  cap: BackendCapabilities,
  request: InterflowReadbackRequest,
  requester: typeof fetch = fetch,
  now: () => number = () => Date.now(),
): Promise<InterflowReadbackResult> {
  assertInterflowReadbackCapability(cap);
  if (!request || !RUN.test(request.runId) ||
    !INDEXES.has(request.index) ||
    !fieldName(request.markerField) || !fieldName(request.expectedField) ||
    typeof request.expectedValue !== 'string' || !VALUES.test(request.expectedValue) ||
    ![1,5,10].includes(request.lookbackMinutes)) {
    throw new Error('Interflow query must use a valid owned run, indexed marker, bounded range and safe scalar field.');
  }
  const endMs = now();
  const startMs = endMs - request.lookbackMinutes * 60000;
  if (!Number.isSafeInteger(startMs) || startMs < 0 || !Number.isSafeInteger(endMs)) {
    throw new Error('Interflow query time range is invalid.');
  }
  const limit = 20;
  const body = {
    index:request.index,runId:request.runId,markerField:request.markerField,
    startMs,endMs,limit,expectedFields:{[request.expectedField]:request.expectedValue},
  };
  const response = await requester('/api/v1/test-lab/interflow/search', {
    method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json',Accept:'application/json'},
    body:JSON.stringify(body),
  });
  if (response.status !== 200) {
    throw new Error('The independently authorized Interflow data read was denied or unavailable (HTTP '+response.status+').');
  }
  let payload: unknown;
  try { payload = await response.json(); }
  catch { throw new Error('The Interflow readback response is not valid JSON.'); }
  return validateInterflowReadback(payload,request.expectedField,limit);
}
