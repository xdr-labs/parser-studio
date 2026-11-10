// Independent comparison of a vendor log's documented field values with the
// event a generated Ruby Fragment actually emitted.
//
// The three inputs come from different places on purpose:
//   - `golden`   : values read from the vendor's own documentation example.
//   - `rows`     : the source -> destination mapping the browser showed the user.
//   - `events`   : what the downloaded Ruby emitted when executed on the raw log.
// Nothing here derives one input from another, so a defect in any one stage
// (extraction, mapping, Ruby generation) shows up as a disagreement.
//
// Scope: Parser Studio output only. This is not a Stellar Cyber import,
// Syslog reception or indexing result.

export interface GoldenValue {
  readonly sourcePath: string;
  readonly sourceValue: unknown;
}

export interface MappingRow {
  /** Source field name exactly as shown in the Map Fields stage. */
  readonly source: string;
  /** Destination field name exactly as shown in the Map Fields stage. */
  readonly target: string;
  /** True when the stage says the field is stored under the manufacturer namespace. */
  readonly vendorNamespace: boolean;
}

export interface EmittedEvent {
  readonly time: unknown;
  readonly record: unknown;
}

export type GoldenProblemCode =
  | 'EVENT_COUNT'
  | 'EVENT_NOT_OBJECT'
  | 'REQUIRED_NOT_IN_GOLDEN'
  | 'REQUIRED_FIELD_UNMAPPED'
  | 'REQUIRED_FIELD_MISSING_IN_EVENT'
  | 'REQUIRED_FIELD_VALUE_MISMATCH'
  | 'AMBIGUOUS_VENDOR_NAMESPACE';

export interface GoldenProblem {
  readonly code: GoldenProblemCode;
  readonly sourcePath: string;
  readonly detail: string;
}

export interface GoldenComparison {
  readonly matched: readonly { sourcePath: string; target: string; value: string }[];
  /** Golden values the mapping does not cover and nobody required. Informational. */
  readonly unrequiredUnmapped: readonly string[];
  readonly problems: readonly GoldenProblem[];
}

const SOURCE_PREFIX = 'parserstudio_source.';

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const normalizeSource = (source: string): string =>
  source.startsWith(SOURCE_PREFIX) ? source.slice(SOURCE_PREFIX.length) : source;

function walk(root: Record<string, unknown>, path: string): { found: boolean; value?: unknown } {
  if (Object.prototype.hasOwnProperty.call(root, path)) return { found: true, value: root[path] };
  let cursor: unknown = root;
  for (const part of path.split('.')) {
    if (!isPlainObject(cursor) || !Object.prototype.hasOwnProperty.call(cursor, part)) return { found: false };
    cursor = cursor[part];
  }
  return { found: true, value: cursor };
}

const text = (value: unknown): string => (typeof value === 'string' ? value : JSON.stringify(value));

// Normalization may legitimately re-render a timestamp (for example adding
// milliseconds or writing the offset with a colon). Two timestamps are the same
// value only when both carry an explicit UTC offset and name the same instant,
// compared at millisecond precision. A timestamp without an offset never
// matches by instant, so a silently assumed time zone still fails.
const ISO_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})$/;

function instantMs(value: string): number | null {
  const match = ISO_INSTANT.exec(value);
  if (!match) return null;
  const [, y, mo, d, h, mi, s, fraction, zone] = match;
  const ms = Number(((fraction ?? '') + '000').slice(0, 3));
  let offsetMinutes = 0;
  if (zone !== 'Z') {
    const digits = zone!.replace(':', '');
    offsetMinutes = (digits[0] === '-' ? -1 : 1) * (Number(digits.slice(1, 3)) * 60 + Number(digits.slice(3, 5)));
  }
  const utc = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms);
  const roundTrip = new Date(utc);
  if (roundTrip.getUTCMonth() !== Number(mo) - 1 || roundTrip.getUTCDate() !== Number(d)) return null;
  return utc - offsetMinutes * 60_000;
}

// The generated Ruby writes the Stellar `timestamp` on the wire as epoch
// milliseconds (see canonical-operator-contract `timestampWireEncoding`), while
// the browser preview shows the canonical UTC ISO form. A 13-digit integer is
// accepted as the same value only when it names the documented instant.
function sameValue(actual: string, expected: string): boolean {
  if (actual === expected) return true;
  const e = instantMs(expected);
  if (e === null) return false;
  if (/^\d{13}$/.test(actual)) return Number(actual) === e;
  const a = instantMs(actual);
  return a !== null && a === e;
}

export function compareEventToGolden(input: {
  readonly golden: readonly GoldenValue[];
  readonly rows: readonly MappingRow[];
  /** Source paths that must be mapped and must round-trip exactly. */
  readonly required: readonly string[];
  readonly events: readonly EmittedEvent[];
}): GoldenComparison {
  const problems: GoldenProblem[] = [];
  const matched: { sourcePath: string; target: string; value: string }[] = [];
  const live = input.events.filter(event => event.record !== null && event.record !== undefined);

  if (live.length !== 1) {
    problems.push({
      code: 'EVENT_COUNT', sourcePath: '*',
      detail: 'expected exactly one emitted event for one raw log, got ' + live.length,
    });
    return { matched, unrequiredUnmapped: [], problems };
  }
  const record = live[0]!.record;
  if (!isPlainObject(record)) {
    problems.push({ code: 'EVENT_NOT_OBJECT', sourcePath: '*', detail: 'emitted record is not an object' });
    return { matched, unrequiredUnmapped: [], problems };
  }

  const goldenByPath = new Map(input.golden.map(item => [item.sourcePath, item.sourceValue] as const));
  const rowBySource = new Map<string, MappingRow>();
  for (const row of input.rows) {
    const key = normalizeSource(row.source);
    if (!rowBySource.has(key)) rowBySource.set(key, row);
  }

  for (const path of input.required) {
    if (!goldenByPath.has(path)) {
      problems.push({ code: 'REQUIRED_NOT_IN_GOLDEN', sourcePath: path, detail: 'no documented value recorded' });
      continue;
    }
    const expected = text(goldenByPath.get(path));
    const row = rowBySource.get(path);
    if (!row) {
      problems.push({ code: 'REQUIRED_FIELD_UNMAPPED', sourcePath: path, detail: 'the Map Fields stage has no row for it' });
      continue;
    }
    let lookup: { found: boolean; value?: unknown };
    if (row.vendorNamespace) {
      const namespaces = Object.values(record).filter(isPlainObject);
      const hits = namespaces.map(ns => walk(ns, row.target)).filter(hit => hit.found);
      if (hits.length > 1) {
        problems.push({ code: 'AMBIGUOUS_VENDOR_NAMESPACE', sourcePath: path, detail: row.target + ' found in several namespaces' });
        continue;
      }
      lookup = hits[0] ?? { found: false };
    } else {
      lookup = walk(record, row.target);
    }
    if (!lookup.found) {
      problems.push({
        code: 'REQUIRED_FIELD_MISSING_IN_EVENT', sourcePath: path,
        detail: row.target + (row.vendorNamespace ? ' (manufacturer namespace)' : '') + ' absent from the emitted event',
      });
      continue;
    }
    const actual = text(lookup.value);
    if (!sameValue(actual, expected)) {
      problems.push({
        code: 'REQUIRED_FIELD_VALUE_MISMATCH', sourcePath: path,
        detail: row.target + ' expected ' + expected + ' but the event holds ' + actual,
      });
      continue;
    }
    matched.push({ sourcePath: path, target: row.target, value: actual });
  }

  const requiredSet = new Set(input.required);
  const unrequiredUnmapped = input.golden
    .map(item => item.sourcePath)
    .filter(path => !requiredSet.has(path) && !rowBySource.has(path));
  return { matched, unrequiredUnmapped, problems };
}
