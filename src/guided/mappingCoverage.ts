import type { MappingRule, SuiteResult } from '../model';
import { lookupFieldValue } from '../fieldPaths';

/** Browser-only counts; never includes source values or implies native/parser acceptance. */
export interface FieldCoverage {
  total: number;
  sourcePresent: number;
  normalized: number;
  missing: number;
  typeFailures: number;
  firstProblemEventId: string | null;
}

export function mappingCoverage(suite: SuiteResult | undefined, mapping: MappingRule): FieldCoverage {
  const events = suite?.events ?? [];
  const result: FieldCoverage = {
    total: events.length, sourcePresent: 0, normalized: 0,
    missing: 0, typeFailures: 0, firstProblemEventId: null,
  };
  for (const event of events) {
    const present = lookupFieldValue(event.fields, mapping.source).found;
    const converted = Object.prototype.hasOwnProperty.call(event.normalized, mapping.target);
    if (present) result.sourcePresent += 1;
    else result.missing += 1;
    if (converted) result.normalized += 1;
    if (present && !converted && event.diagnostics.some(
      diagnostic => diagnostic.code === 'TYPE_ERROR' && diagnostic.field === mapping.source,
    )) result.typeFailures += 1;
    if (!converted && result.firstProblemEventId === null) result.firstProblemEventId = event.id;
  }
  return result;
}
