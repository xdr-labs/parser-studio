/**
 * Source field names the JavaScript object model reserves (G-5).
 *
 * A log may carry a field called `__proto__`, `constructor` or `prototype` (contract kvForbiddenKeys). Writing such
 * a name into an object of the browser can change the object's prototype instead of creating a field, so these
 * events used to be refused, and the values were not parsed. They are now kept under a reversible name: the prefix
 * `parserstudio_key_` is put in front of a reserved name, and in front of every source name that already starts with
 * that prefix. Different source names therefore never share a name (the mapping is injective), and
 * originalFieldName gives the source name back. Every other name is unchanged.
 *
 * Part of the shared grammar: the KV, CEF, LEEF and JSON readers and their loss guards use it, the generated Ruby
 * runs the translation (scripts/grammar/ts2rb), and the Python Multi-Pass readers apply the same rule
 * (runtime/multipass/source_field_names.py).
 */
import { SYSLOG_HEADER_SEMANTICS } from './syslogHeaderGrammar.generated';

export const SOURCE_NAME_PREFIX = 'parserstudio_key_';
const RESERVED: readonly string[] = SYSLOG_HEADER_SEMANTICS.kvForbiddenKeys;

/** The field name a source name is kept under. */
export function sourceFieldName(name: string): string {
  return RESERVED.includes(name) || name.startsWith(SOURCE_NAME_PREFIX) ? SOURCE_NAME_PREFIX + name : name;
}

/** The source name a field name stands for (the inverse of sourceFieldName). */
export function originalFieldName(name: string): string {
  return name.startsWith(SOURCE_NAME_PREFIX) ? name.slice(SOURCE_NAME_PREFIX.length) : name;
}

function needsRenaming(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(needsRenaming);
  if (value === null || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).some(name => sourceFieldName(name) !== name || needsRenaming(record[name]));
}

function renamed(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(renamed);
  if (value === null || typeof value !== 'object') return value;
  const record = value as Record<string, unknown>;
  // sourceFieldName never returns a reserved name, so a plain assignment cannot reach the prototype.
  const out: Record<string, unknown> = {};
  for (const name of Object.keys(record)) out[sourceFieldName(name)] = renamed(record[name]);
  return out;
}

/** A decoded JSON value with every member name kept under its field name; the same value when nothing changes. */
export function withSourceFieldNames(value: unknown): unknown {
  return needsRenaming(value) ? renamed(value) : value;
}
