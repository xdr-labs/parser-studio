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
const ALLOWED_FORMATS = ['json', 'kv', 'csv', 'syslog_rfc3164', 'syslog_rfc5424', 'cef', 'leef', 'mixed'];
const ALLOWED_TYPES = ['string', 'integer', 'ip', 'port', 'boolean', 'date'];
const ALLOWED_CATEGORIES = ['network', 'endpoint', 'cloud', 'application', 'other'];
const ALLOWED_PROTOCOLS = ['udp', 'tcp'];

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Required schema contract could not be verified.');
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
    throw new Error('Backend field definitions are unsupported or ambiguous.');
  }
  return input;
}
function boundedInteger(input: unknown, lower: number, upper: number): number {
  if (!Number.isInteger(input) || Number(input) < lower || Number(input) > upper) {
    throw new Error('Backend schema value ranges are unsupported.');
  }
  return Number(input);
}

export function parseBackendSchemaGuide(input: unknown): BackendSchemaGuide {
  if (member(input, '$id') !== 'urn:xdr-labs:parser-project:v0.1' ||
      member(input, '$schema') !== 'http://json-schema.org/draft-07/schema#' ||
      member(input, 'properties', 'schemaRevision', 'const') !== '0.1') {
    throw new Error('Unsupported ParserProject schema revision.');
  }
  const formats = knownEnums(member(input, 'properties','extraction','properties','format','enum'), ALLOWED_FORMATS);
  const types = knownEnums(member(input, '$defs','fieldRule','properties','data_type','enum'), ALLOWED_TYPES);
  const categories = knownEnums(member(input, 'properties','sourceCategory','enum'), ALLOWED_CATEGORIES);
  const protocols = knownEnums(member(input, 'properties','receiver','properties','protocols','items','enum'), ALLOWED_PROTOCOLS);
  const sourceName = record(member(input, '$defs','mapping','propertyNames'));
  const targetName = record(member(input, '$defs','fieldRule','properties','normalized_name'));
  if (sourceName.pattern !== FIELD_PATH_PATTERN || targetName.pattern !== FIELD_PATH_PATTERN) {
    throw new Error('Schema guidance blocked due to unverified field naming rules.');
  }
  const sourceMax = boundedInteger(sourceName.maxLength, 1, 128);
  const targetMax = boundedInteger(targetName.maxLength, 1, 128);
  if (sourceMax !== targetMax) throw new Error('Input and output field name rules do not match.');
  const receiver = member(input,'properties','receiver','properties');
  const p = record(member(receiver,'port'));
  const m = record(member(receiver,'messageLengthLimit'));
  if (p.type !== 'integer' || m.type !== 'integer') {
    throw new Error('Port or message size constraints are unsupported.');
  }
  const port = { min: boundedInteger(p.minimum, 1, 65535), max: boundedInteger(p.maximum, 1, 65535) };
  const messageLength = { min: boundedInteger(m.minimum, 256, 65536), max: boundedInteger(m.maximum, 256, 65536) };
  if (port.min > port.max || messageLength.min > messageLength.max) {
    throw new Error('Backend schema contains invalid allowed ranges.');
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
  if (response.status !== 200) throw new Error('Backend schema request failed (HTTP ' + response.status + ').');
  let body: unknown;
  try { body = await response.json(); } catch {
    throw new Error('Backend returned an invalid JSON schema.');
  }
  return parseBackendSchemaGuide(body);
}
