/**
 * Read-only projection of the current local backend ParserProject JSON Schema.
 * This is an authoring contract, never an official Stellar Cyber/Interflow field dictionary.
 * Do not render arbitrary schema text or execute patterns supplied by a backend.
 */
export interface BackendSchemaGuide {
  revision: '0.1';
  formats: string[];
  fieldTypes: string[];
  sourceCategories: string[];
  receiverProtocols: string[];
  fieldNamePattern: string;
  fieldNameMaxLength: number;
  port: { min: number; max: number };
  messageLength: { min: number; max: number };
}

const BASE = '/api/v1/parser-pairs/schema';
const FIELD_PATH_PATTERN = String.raw`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$`;
const ALLOWED_FORMATS = ['json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef'];
const ALLOWED_TYPES = ['string', 'integer', 'ip', 'port', 'boolean', 'date'];
const ALLOWED_CATEGORIES = ['network', 'endpoint', 'cloud', 'application', 'other'];
const ALLOWED_PROTOCOLS = ['udp', 'tcp'];

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('백엔드 스키마에서 필수 계약을 확인할 수 없습니다.');
  }
  return value as Record<string, unknown>;
}
function member(root: unknown, ...keys: string[]): unknown {
  let current = root;
  for (const key of keys) current = record(current)[key];
  return current;
}
function knownEnums(input: unknown, allowed: readonly string[]): string[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > allowed.length ||
      !input.every((value) => typeof value === 'string' && allowed.includes(value)) ||
      new Set(input).size !== input.length) {
    throw new Error('지원하지 않거나 모호한 백엔드 필드 규격입니다.');
  }
  return input;
}
function boundedInteger(input: unknown, lower: number, upper: number): number {
  if (!Number.isInteger(input) || Number(input) < lower || Number(input) > upper) {
    throw new Error('백엔드 스키마 값의 범위가 지원되지 않습니다.');
  }
  return Number(input);
}

export function parseBackendSchemaGuide(input: unknown): BackendSchemaGuide {
  if (member(input, '$id') !== 'urn:xdr-labs:parser-project:v0.1' ||
      member(input, '$schema') !== 'http://json-schema.org/draft-07/schema#' ||
      member(input, 'properties', 'schemaRevision', 'const') !== '0.1') {
    throw new Error('지원되지 않는 ParserProject 스키마 버전입니다.');
  }
  const formats = knownEnums(member(input, 'properties','extraction','properties','format','enum'), ALLOWED_FORMATS);
  const types = knownEnums(member(input, '$defs','fieldRule','properties','data_type','enum'), ALLOWED_TYPES);
  const categories = knownEnums(member(input, 'properties','sourceCategory','enum'), ALLOWED_CATEGORIES);
  const protocols = knownEnums(member(input, 'properties','receiver','properties','protocols','items','enum'), ALLOWED_PROTOCOLS);
  const sourceName = record(member(input, '$defs','mapping','propertyNames'));
  const targetName = record(member(input, '$defs','fieldRule','properties','normalized_name'));
  if (sourceName.pattern !== FIELD_PATH_PATTERN || targetName.pattern !== FIELD_PATH_PATTERN) {
    throw new Error('검증되지 않은 필드 이름 규칙이어서 스키마 안내를 차단했습니다.');
  }
  const sourceMax = boundedInteger(sourceName.maxLength, 1, 128);
  const targetMax = boundedInteger(targetName.maxLength, 1, 128);
  if (sourceMax !== targetMax) throw new Error('입력/출력 필드 규격이 서로 일치하지 않습니다.');
  const receiver = member(input,'properties','receiver','properties');
  const p = record(member(receiver,'port'));
  const m = record(member(receiver,'messageLengthLimit'));
  if (p.type !== 'integer' || m.type !== 'integer') {
    throw new Error('포트 및 메시지 크기 규격이 지원되지 않습니다.');
  }
  const port = { min: boundedInteger(p.minimum, 1, 65535), max: boundedInteger(p.maximum, 1, 65535) };
  const messageLength = { min: boundedInteger(m.minimum, 256, 65536), max: boundedInteger(m.maximum, 256, 65536) };
  if (port.min > port.max || messageLength.min > messageLength.max) {
    throw new Error('백엔드 스키마의 허용 범위가 잘못되었습니다.');
  }
  return {
    revision: '0.1', formats, fieldTypes: types, sourceCategories: categories,
    receiverProtocols: protocols, fieldNamePattern: FIELD_PATH_PATTERN,
    fieldNameMaxLength: sourceMax, port, messageLength,
  };
}

export async function fetchBackendSchemaGuide(requester: typeof fetch = fetch): Promise<BackendSchemaGuide> {
  const response = await requester(BASE, {
    method: 'GET', credentials: 'same-origin', cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  if (response.status !== 200) throw new Error('백엔드 스키마 조회가 실패했습니다 (HTTP ' + response.status + ').');
  let body: unknown;
  try { body = await response.json(); } catch {
    throw new Error('백엔드가 올바른 JSON 스키마를 반환하지 않았습니다.');
  }
  return parseBackendSchemaGuide(body);
}
