import {evaluateCanonicalClassificationPredicate} from '../../backend/src/canonical-operator-contract';
import type { EventResult,ParserDraft } from '../model';
import type { EventClass, GuidedOptions } from './contract';
import { lookupFieldValue } from '../fieldPaths';

export interface ClassificationHint {
  index: EventClass | null;
  rule: number | null;
  reason: string;
  status: 'matched' | 'fallback' | 'unresolved';
}

/** Browser-only ordered if/then hint; NOT evidence of real Fluentd rewrite-tag or target upload. */
export function suggestClassification(event: EventResult, options: GuidedOptions,
  draft?:ParserDraft): ClassificationHint {
  if (!event.matched) {
    return { index: null, rule: null, status: 'unresolved', reason: 'Event extraction failed; unable to classify.' };
  }
  for (let i = 0; i < options.classification.rules.length; i++) {
    const rule = options.classification.rules[i];
    if (!rule.sourceField.trim() || !rule.equals.trim()) continue;
    const mapping=draft?.mappings.find(candidate=>candidate.source===rule.sourceField&&
      (options.groups[candidate.id]??'vendor_fields')!=='vendor_fields');
    // In the real Native parser, classification runs AFTER typed mapping.
    // A missing or non-string mapped destination cannot satisfy a string
    // equality rule, even if String(originalNumber) would have matched.
    const match=draft
      ?(mapping?.type==='string'
          ?lookupFieldValue(event.normalized,mapping.target)
          :{found:false,value:undefined})
      :lookupFieldValue(event.fields,rule.sourceField.trim());
    if(match.found&&evaluateCanonicalClassificationPredicate('equals',match.value,rule.equals)){
      return { index: rule.index, rule: i, status: 'matched', reason: rule.sourceField + ' = ' + rule.equals + ' · Condition ' + (i + 1) };
    }
  }
  return { index: options.classification.defaultIndex, rule: null, status: 'fallback', reason: 'No condition matched · Applied default event category' };
}
