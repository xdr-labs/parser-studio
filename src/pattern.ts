export interface FieldProposal {
  sourceValue: string;
  field: string;
  pattern: string;
  caveat: string;
}

// Generates a deliberately sample-specific starter. Never runtime-verification evidence.
function escapeLiteral(text: string): string {
  return text.replace(/[.*+?^\$\{\}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
}

export function createFieldProposal(raw: string, selected: string, inputField: string): FieldProposal | { error: string } {
  const field = inputField.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(field)) return { error: 'Field names must contain letters, numbers or underscore, starting with a letter or underscore' };
  if (!selected || selected.includes('\n') || selected.length > 80) return { error: 'Select one event value up to 80 characters' };
  const offset = raw.indexOf(selected);
  if (offset < 0) return { error: 'Selected value is no longer present in this event' };
  if (raw.indexOf(selected, offset + 1) >= 0) return { error: 'Value repeats in this event; choose a less ambiguous sample' };
  const prefix = raw.slice(0, offset);
  const suffix = raw.slice(offset + selected.length);
  const capture = /\s/.test(selected) ? '.+?' : '\\S+';
  const pattern = '^' + escapeLiteral(prefix) + '(?<' + field + '>' + capture + ')' + escapeLiteral(suffix) + '$';
  if (pattern.length > 256) return { error: 'Selection is in a sample too long for the 256-character preview regex limit' };
  return {
    sourceValue: selected, field, pattern,
    caveat: 'Sample-specific starter pattern. Test on the full dataset before acceptance; Fluentd compatibility has not been verified.',
  };
}
