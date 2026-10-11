export interface FieldProposal {
  sourceValue: string;
  field: string;
  pattern: string;
  caveat: string;
}

function escapeKey(key: string): string {
  return key.replace(/[.*+?^$()|[\]{}\\]/g, '\\$&');
}

const QUOTE = "['\"]";

/**
 * Build a starter from an immediately adjacent JSON or KV field label only.
 * Do not copy the surrounding raw sample into saved patterns: real values may be private.
 * Unsupported free text must be authored through the advanced rule editor.
 */
export function createFieldProposal(raw: string, selected: string, inputField: string): FieldProposal | { error: string } {
  const field = inputField.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(field)) {
    return { error: 'Field names must start with a letter/underscore, use only letters/digits/underscore and be at most 64 characters' };
  }
  if (!selected || selected.includes('\n') || selected.length > 80) {
    return { error: 'Select one value up to 80 characters from a single event' };
  }
  const offset = raw.indexOf(selected);
  if (offset < 0) return { error: 'Selected value is no longer present in the event' };
  if (raw.indexOf(selected, offset + 1) >= 0) {
    return { error: 'Value repeats in one event; choose a less ambiguous sample' };
  }
  if (/['"\\]/.test(selected)) {
    return { error: 'Escaped or quoted values are not supported by this visual starter; use an explicit parser rule' };
  }
  const preceding = raw.slice(0, offset);
  const after = raw[offset + selected.length] ?? '';
  const jsonKey = preceding.match(/["']([A-Za-z_][A-Za-z0-9_.-]{0,63})["']\s*:\s*(["']?)$/);
  const kvKey = preceding.match(/(?:^|[\s,;])([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*=\s*(["']?)$/);
  let pattern: string;
  if (jsonKey && jsonKey[2]) {
    if (after !== jsonKey[2]) return { error: 'Select the complete JSON string field value' };
    pattern = QUOTE + escapeKey(jsonKey[1]) + QUOTE + '\\s*:\\s*' + QUOTE +
      '(?<' + field + '>[^\\x22\\x27\\\\]+)' + QUOTE;
  } else if (jsonKey) {
    if (!/^(?:-?\d+(?:\.\d+)?|true|false|null)$/.test(selected)) {
      return { error: 'Select a complete JSON numeric, boolean or null field value' };
    }
    pattern = QUOTE + escapeKey(jsonKey[1]) + QUOTE +
      '\\s*:\\s*(?<' + field + '>-?\\d+(?:\\.\\d+)?|true|false|null)(?:[,}\\s]|$)';
  } else if (kvKey && kvKey[2]) {
    if (after !== kvKey[2]) return { error: 'Select the complete quoted key-value field' };
    pattern = '(?:^|\\s)' + escapeKey(kvKey[1]) + '\\s*=\\s*' + QUOTE +
      '(?<' + field + '>[^\\x22\\x27\\\\]+)' + QUOTE;
  } else if (kvKey) {
    if (after && !/[\s,;}]/.test(after)) return { error: 'Select the complete key=value token' };
    pattern = '(?:^|\\s)' + escapeKey(kvKey[1]) + '\\s*=\\s*(?<' + field + '>[^\\s,;}]+)';
  } else {
    return { error: 'Select a field value after a JSON key or key= label. Advanced formats require explicit rules.' };
  }
  if (pattern.length > 256) return { error: 'Generated preview pattern exceeds the size limit' };
  return {
    sourceValue: selected,
    field,
    pattern,
    caveat: 'Structural JSON/KV starter only, with no original sample values embedded. Preview all events; native Fluentd compatibility is unverified.',
  };
}
