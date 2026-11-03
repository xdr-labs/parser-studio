/**
 * Guard original numeric lexemes before JSON.parse can round large event IDs.
 * The caller validates JSON syntax first. This scanner ignores JSON strings,
 * including escaped quotation marks, and examines every nested number.
 *
 * Large/inexact integer tokens are not reviewer-safe in JavaScript Number.
 * Excessively precise decimals are conservatively deferred for manual review.
 */
export function hasUnsafeJsonNumbers(source: string): boolean {
  let index = 0;
  while (index < source.length) {
    const current = source[index]!;
    if (current === '"') {
      index++;
      while (index < source.length) {
        if (source[index] === '\\') { index += 2; continue; }
        if (source[index++] === '"') break;
      }
      continue;
    }
    if (current === '-' || (current >= '0' && current <= '9')) {
      const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(index));
      if (!match) return true;
      const token = match[0];
      const value = Number(token);
      if (!Number.isFinite(value)) return true;
      if (Number.isInteger(value) && !Number.isSafeInteger(value)) return true;
      // Decimal/scientific representations with too many meaningful digits
      // can differ across JavaScript and the generated Ruby runtime.
      if (/[.eE]/.test(token)) {
        const mantissa = token.split(/[eE]/, 1)[0]!;
        const significant = mantissa.replace(/^[+-]?0*/, '').replace('.', '').replace(/0+$/, '');
        if (significant.length > 15) return true;
        // Don't silently treat a nonzero decimal as zero after underflow.
        if (value === 0 && /[1-9]/.test(mantissa)) return true;
      }
      index += token.length;
      continue;
    }
    index++;
  }
  return false;
}
