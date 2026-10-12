/**
 * Conservative preview-only regular-expression linter. The separate Web Worker
 * still enforces an execution timeout, and this check is NOT a proof that all
 * accepted JS regexes have linear complexity or match native Ruby/Fluentd.
 */
export function validatePreviewRegexPattern(pattern: string): string | null {
  if (!pattern.trim()) return 'Enter a named-group regular expression';
  if (pattern.length > 256) return 'Regex exceeds 256 characters';
  if (!pattern.includes('(?<')) return 'Add at least one (?<field>...) named capture';

  const unsupported = 'Regex uses an unsupported or potentially expensive construct';

  // Backreferences and lookbehind enable nonlocal matching/ambiguous nesting.
  if (/\\[1-9]|\\k<|\(\?<[=!]/.test(pattern)) return unsupported;

  // These forms can yield exponential backtracking even with short input:
  // repeated groups containing quantifiers, optional terms or alternatives.
  if (/\((?:[^()]|\\.)*[+*?](?:[^()]|\\.)*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern)) {
    return unsupported;
  }
  if (/\((?:\?:)?[^()]*\|[^()]*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern)) {
    return unsupported;
  }
  // Adjacent repetitions of the identical literal character are ambiguous.
  if (/([A-Za-z0-9])(?:[*+])\1(?:[*+])/.test(pattern)) return unsupported;

  // Prohibit very large unrolled repetition budgets, even without nested
  // quantifiers; the user can rewrite these as smaller typed expressions.
  for (const match of pattern.matchAll(/\{(\d{1,8})(?:,(\d{0,8}))?\}/g)) {
    const low = Number(match[1]);
    const high = match[2] === undefined || match[2] === '' ? low : Number(match[2]);
    if (low > 128 || high > 128) return unsupported;
  }
  return null;
}
