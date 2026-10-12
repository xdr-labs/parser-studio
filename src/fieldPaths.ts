/**
 * Browser-local conservative, bounded projection of ParserProject 0.1 dotted
 * source paths. Backend lookup prefers an exact literal key before descending
 * nested JSON objects. Never traverse inherited/prototype or array-index paths.
 */
const PATH = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_DEPTH = 8;
const MAX_FIELDS = 100;

export function safeLocalFieldPath(path: string): boolean {
  return path.length > 0 && path.length <= 128 && PATH.test(path) &&
    path.split('.').every((segment) => !UNSAFE.has(segment));
}

function objectRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function lookupFieldValue(
  fields: Record<string, unknown>, path: string,
): { found: true; value: unknown } | { found: false } {
  if (!safeLocalFieldPath(path) || path.split('.').length > MAX_DEPTH) return { found: false };
  // Match the backend's first direct-key check for flat KV keys containing dots.
  if (Object.prototype.hasOwnProperty.call(fields, path)) {
    return { found: true, value: fields[path] };
  }
  let value: unknown = fields;
  for (const segment of path.split('.')) {
    if (!objectRecord(value) || !Object.prototype.hasOwnProperty.call(value, segment)) {
      return { found: false };
    }
    value = value[segment];
  }
  return { found: true, value };
}

/** Returns only safe leaf *names*, never log values, bounded at 100 paths. */
export function listSafeLeafPaths(fields: Record<string, unknown>): string[] {
  const results: string[] = [];
  const seen = new Set<string>();
  const visit = (value: unknown, prefix: string, depth: number) => {
    if (results.length >= MAX_FIELDS || depth > MAX_DEPTH || (prefix && !safeLocalFieldPath(prefix))) return;
    if (objectRecord(value)) {
      if (depth === MAX_DEPTH) return;
      for (const key of Object.keys(value)) {
        if (results.length >= MAX_FIELDS) break;
        const next = prefix ? prefix + '.' + key : key;
        if (!safeLocalFieldPath(next)) continue;
        visit(value[key], next, depth + 1);
      }
    } else if (prefix && value !== null && !Array.isArray(value) && !seen.has(prefix)) {
      seen.add(prefix);
      results.push(prefix);
    }
  };
  visit(fields, '', 0);
  return results;
}
