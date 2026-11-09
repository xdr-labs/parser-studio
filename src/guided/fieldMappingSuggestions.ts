import type { MappingRule, ParserDraft } from '../model';
import { defaultGuidedOptions, type FieldGroup } from './contract';
import { listSafeLeafPaths } from '../fieldPaths';
import { findStellarMetadataField } from './stellarMetadataCatalog';
import {vendorFieldNames} from './vendorFieldNames';

export interface SuggestedFieldMapping {
  source: string;
  target: string;
  type: MappingRule['type'];
  group: FieldGroup;
}

const SAFE_PATH = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
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

  // Do not let one wide JSON event consume the entire 100-mapping budget.
  // Mixed security samples often have disjoint JSON/KV/CEF/LEEF field names;
  // round-robin candidates across events so every represented family can keep
  // at least some source-backed output without raising the global safety cap.
  const queues = samples.map(fields => listSafeLeafPaths(fields));
  const names=vendorFieldNames(queues.flat().filter(source=>!existingSources.has(source)),taken);
  while (proposals.length < 100) {
    let addedThisRound = false;
    let candidatesRemain = false;
    for (const queue of queues) {
      while (queue.length) {
        candidatesRemain = true;
        const source = queue.shift()!;
        if (found.has(source) || existingSources.has(source) || !SAFE_PATH.test(source)) continue;
        found.add(source);
        if (source.split('.').some(segment => DANGEROUS.has(segment) || !segment)) continue;
        // Prefer the last original path component. Duplicate leaf names fall
        // back to their exact source paths without dot-to-underscore mangling.
        const normalized = names.get(source);
        if (SYSTEM.has(source.split('.')[0]) || !normalized) continue;
        if (taken.some(target => conflicts(target, normalized))) continue;
        const proposal: SuggestedFieldMapping = {
          source, target: normalized, type: 'string',
          group: classifierFields.has(source)&&findStellarMetadataField(normalized)?.mappable ? 'top_fields' : 'vendor_fields',
        };
        proposals.push(proposal);
        taken.push(normalized);
        addedThisRound = true;
        break;
      }
      if (proposals.length >= 100) break;
    }
    if (!candidatesRemain || !addedThisRound) break;
  }
  return proposals;
}
