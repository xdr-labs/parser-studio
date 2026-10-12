import type { FieldType, MappingRule, SuiteResult } from '../model';
import { convertValue } from '../parser';
import { lookupFieldValue } from '../fieldPaths';

export interface MappingTypeSuggestion {
  type: FieldType;
  evidence: number;
  total: number;
}

/** Conservative local-only guess, never a vendor field definition.
 * Requires two relevant samples, and never exposes or persists observed values.
 */
export function suggestMappingType(
  suite: SuiteResult | undefined,
  mapping: MappingRule,
): MappingTypeSuggestion | null {
  if (!suite || suite.events.length < 2) return null;
  const values: unknown[] = [];
  for (const event of suite.events) {
    const found = lookupFieldValue(event.fields, mapping.source);
    if (!found.found || found.value === undefined || found.value === null ||
        typeof found.value === 'object' || String(found.value).trim() === '') continue;
    values.push(found.value);
  }
  if (values.length < 2) return null;
  const every = (type: FieldType) => values.every(value => convertValue(value,type).error === undefined);
  let type: FieldType | null = null;
  if (values.every(value => typeof value === 'string' &&
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) && every('ip')) {
    type = 'ip';
  } else if (/(?:^|[_.])port$/i.test(mapping.source) &&
      values.every(value => {
        const text = String(value);
        return /^\d+$/.test(text) && Number(text) >= 1 && Number(text) <= 65535;
      }) && every('port')) {
    type = 'port';
  } else if (values.every(value => typeof value === 'boolean' ||
      (typeof value === 'string' && /^(?:true|false)$/i.test(value))) && every('boolean')) {
    type = 'boolean';
  } else if (values.every(value => typeof value === 'string' &&
      /(?:Z|[+-]\d{2}:\d{2})$/.test(value)) && every('timestamp')) {
    type = 'timestamp';
  } else if (/(?:^|[_.])(?:count|total|bytes|size|attempts|seq|duration)$/i.test(mapping.source) &&
      every('integer')) {
    type = 'integer';
  }
  return type === null ? null : { type, evidence: values.length, total: suite.events.length };
}
