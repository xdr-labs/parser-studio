/**
 * Parsing Success Contract for Generic Structural results (W7, owner policy D-2).
 *
 *   FULL     every key=value pair of the original line is an extracted field, or is inside a text field the
 *            mode keeps (a message, a prefix); and the line was read by the grammar it claims
 *   PARTIAL  a pair is in no field at all, or a line that claims to be CEF/LEEF was read as generic
 *            key=value (its header is not parsed): the original text is kept, the result is not complete
 *   UNKNOWN  the bounded grammar declined the line; nothing is parsed
 *   ERROR    the extractor raised
 *
 * The verdict is the same for every mode because it is decided from the original line and the result, not
 * from the mode's own grammar. The copies of the original text that every mode carries for provenance
 * (source_raw, message_raw) are not counted as fields.
 */
import { independentKeyValuePairs, type ParseVerdict, type RawPair, type StructuredOutcome } from './parseStatus';
import { GENERIC_FAMILY_MODES, structuredFamilyClaim } from '../genericStructural';

const PROVENANCE_COPIES: readonly string[] = ['source_raw', 'message_raw'];

function collect(value: unknown, key: string, out: Array<[string, string]>): void {
  if (Array.isArray(value)) { for (const child of value) collect(child, key, out); return; }
  if (value !== null && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) collect(child, childKey, out);
    return;
  }
  if (value !== undefined && value !== null && !PROVENANCE_COPIES.includes(key)) out.push([key, String(value)]);
}

const withoutBackslashes = (text: string) => text.split('\\').join('');

/** A pair is accounted for when a field of that name holds its value, or a kept text field holds the pair as written. */
function accounted(pair: RawPair, leaves: Array<[string, string]>): boolean {
  const written = withoutBackslashes(pair.rawValue);
  return leaves.some(([key, value]) => (key === pair.key && (
    value === pair.value || value === pair.rawValue || withoutBackslashes(value) === written ||
    // A mode whose values run to the next key keeps the token and what follows it.
    value.startsWith(pair.value + ' ') || withoutBackslashes(value).startsWith(written + ' '))) ||
    (value.includes(pair.key + '=') && value.includes(pair.rawValue)));
}

export function classifyGenericStructural(raw: string, outcome: StructuredOutcome | { thrown: unknown }): ParseVerdict & { mode?: string } {
  if ('thrown' in outcome) return { status: 'ERROR', lostPairs: [], reasons: ['extractor raised: ' + String(outcome.thrown)] };
  if (outcome.errors.length > 0) return { status: 'UNKNOWN', lostPairs: [], reasons: outcome.errors.slice(0, 4) };
  if (Object.keys(outcome.fields).length === 0) return { status: 'UNKNOWN', lostPairs: [], reasons: ['no field was extracted'] };
  const generic = outcome.fields.generic as { mode?: unknown } | undefined;
  const mode = typeof generic?.mode === 'string' ? generic.mode : Object.keys(outcome.fields).filter(key => key !== 'syslog').join('+');
  const reasons: string[] = [];
  const claim = structuredFamilyClaim(raw);
  if (claim && !GENERIC_FAMILY_MODES.includes(mode))
    reasons.push('the line claims to be ' + claim + ' but was read as generic key=value (legacy compatibility route): its ' + claim + ' header is not parsed');
  const leaves: Array<[string, string]> = [];
  collect(outcome.fields, '', leaves);
  const lostPairs = independentKeyValuePairs(raw).filter(pair => !accounted(pair, leaves));
  for (const pair of lostPairs.slice(0, 4)) reasons.push('raw pair ' + pair.key + '= is not present with its value in the extracted fields');
  return { status: reasons.length > 0 ? 'PARTIAL' : 'FULL', lostPairs, reasons, mode };
}
