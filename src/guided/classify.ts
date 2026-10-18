import type { EventResult } from '../model';
import type { EventClass, GuidedOptions } from './contract';
import { lookupFieldValue } from '../fieldPaths';

export interface ClassificationHint {
  index: EventClass | null;
  rule: number | null;
  reason: string;
  status: 'matched' | 'fallback' | 'unresolved';
}

/** Browser-only ordered if/then hint; NOT evidence of real Fluentd rewrite-tag or target upload. */
export function suggestClassification(event: EventResult, options: GuidedOptions): ClassificationHint {
  if (!event.matched) {
    return { index: null, rule: null, status: 'unresolved', reason: 'Event extraction failed; unable to classify.' };
  }
  for (let i = 0; i < options.classification.rules.length; i++) {
    const rule = options.classification.rules[i];
    if (!rule.sourceField.trim() || !rule.equals.trim()) continue;
    const match = lookupFieldValue(event.fields, rule.sourceField.trim());
    if (match.found && match.value !== null && match.value !== undefined &&
        String(match.value) === rule.equals) {
      return { index: rule.index, rule: i, status: 'matched', reason: rule.sourceField + ' = ' + rule.equals + ' · Condition ' + (i + 1) };
    }
  }
  return { index: options.classification.defaultIndex, rule: null, status: 'fallback', reason: 'No condition matched · Applied default event category' };
}
