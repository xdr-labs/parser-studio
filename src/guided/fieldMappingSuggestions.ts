import type { MappingRule, ParserDraft } from '../model';
import { defaultGuidedOptions, type FieldGroup } from './contract';

export interface SuggestedFieldMapping {
  source: string;
  target: string;
  type: MappingRule['type'];
  group: FieldGroup;
}

const SAFE_PATH = /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/;
const DANGEROUS = new Set(['__proto__', 'prototype', 'constructor']);
const SYSTEM = new Set(['msg_origin', 'stellar_log_index', 'parser_err_msg']);

function conflicts(a: string, b: string): boolean {
  return a === b || a.startsWith(b + '.') || b.startsWith(a + '.');
}

/** Source keys only, not sample values; suggestions are conservative string mappings.
 * Nothing is applied until the user explicitly confirms in the Guided UI. */
export function suggestUnmappedFields(
  samples: Array<Record<string, unknown>>,
  draft: ParserDraft,
): SuggestedFieldMapping[] {
  const existingSources = new Set(draft.mappings.map(mapping => mapping.source.trim()));
  const taken = draft.mappings.map(mapping => mapping.target.trim());
  const classifierFields = new Set(
    (draft.guided ?? defaultGuidedOptions()).classification.rules.map(rule => rule.sourceField),
  );
  const found = new Set<string>();
  const proposals: SuggestedFieldMapping[] = [];

  for (const fields of samples) {
    for (const source of Object.keys(fields)) {
      if (proposals.length >= 50) return proposals;
      if (found.has(source) || existingSources.has(source) || !SAFE_PATH.test(source)) continue;
      found.add(source);
      if (source.split('.').some(segment => DANGEROUS.has(segment) || !segment)) continue;
      const normalized = 'custom.' + source.replace(/\./g, '_');
      if (SYSTEM.has(source.split('.')[0]) || normalized.length > 128) continue;
      if (taken.some(target => conflicts(target, normalized))) continue;
      const proposal: SuggestedFieldMapping = {
        source, target: normalized, type: 'string',
        group: classifierFields.has(source) ? 'top_fields' : 'vendor_fields',
      };
      proposals.push(proposal);
      taken.push(normalized);
    }
  }
  return proposals;
}
