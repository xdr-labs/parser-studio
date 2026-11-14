/**
 * Property-based case generator for a JSON object event.
 *
 * An event is rendered from the values the sender MEANT, in several spellings
 * that RFC 8259 defines as equal: compact, with insignificant white space, with
 * every non-ASCII character and "/" written as an escape, with the members in
 * reverse order. The expectation is the meant value, never the result of
 * parsing the rendered text.
 *
 * Texts that RFC 8259 does not allow are expected to be declined: a trailing
 * comma, single-quoted or bare names, a truncated object, text after the
 * object, a number with a leading zero, NaN. A repeated member name is declined
 * by product policy (RFC 8259 section 4 leaves the result undefined). An
 * integer beyond 2^53 may be declined, but if it is reported it must carry
 * exactly the digits that were written.
 */
export type JsonValue = string | number | boolean | null;
export interface JsonCase {
  id: string;
  raw: string;
  provenance: string;
  expect: { status: 'FULL' | 'UNKNOWN'; neverWrong?: boolean; values?: Record<string, JsonValue>; exactDigits?: Record<string, string> };
}

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const STRINGS = ['allow', 'say "hi" now', 'C:\\dir\\f', 'line1\nline2', 'tab\there', 'a/b', '\u00e9t\u00e9', '\uD83D\uDE00 ok', 'a\u2028b', '\uD55C\uAD6D\uC5B4 \uB85C\uADF8', '', 'k=v', '{"not":"nested"}'];
/** [meant number, text] - texts RFC 8259 defines as that number. */
const NUMBERS: ReadonlyArray<readonly [number, string]> = [[0, '0'], [443, '443'], [-1, '-1'], [65535, '65535'], [0.5, '0.5'], [1000, '1e3'], [9007199254740991, '9007199254740991'], [-12.25, '-12.25']];

const stringText = (value: string, escapeAll: boolean) => {
  let out = '"';
  for (const unit of value.split('')) {
    const code = unit.charCodeAt(0);
    if (unit === '"') out += '\\"';
    else if (unit === '\\') out += '\\\\';
    else if (unit === '\n') out += '\\n';
    else if (unit === '\t') out += '\\t';
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
    else if (escapeAll && unit === '/') out += '\\/';
    else if (escapeAll && code > 0x7e) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += unit;
  }
  return out + '"';
};

export function generateJsonCases(count: number, seed: number): JsonCase[] {
  const random = mulberry32(seed);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const cases: JsonCase[] = [];
  for (let index = 0; index < count; index += 1) {
    const number = pick(NUMBERS);
    const flat: Array<[string, JsonValue, string | null]> = [
      ['srcip', pick(['10.1.1.1', '192.168.0.254']), null], ['action', pick(['allow', 'deny']), null],
      ['msg', pick(STRINGS), null], ['note', pick(STRINGS), null], ['count', number[0], number[1]],
      ['flag', pick([true, false]), null], ['none', null, null],
    ];
    const nested: Array<[string, JsonValue]> = [['name', pick(['alice', 'user@example.com', '\uD55C\uAD6D\uC5B4'])], ['id', pick([7, 1001])]];
    const expectValues: Record<string, JsonValue> = Object.fromEntries([...flat.map(([name, value]) => [name, value]), ...nested.map(([name, value]) => ['user.' + name, value])]);
    const render = (options: { escapeAll?: boolean; spaced?: boolean; reversed?: boolean } = {}) => {
      const text = (value: JsonValue, written: string | null) => written ?? (typeof value === 'string' ? stringText(value, !!options.escapeAll) : String(value));
      const gap = options.spaced ? ' ' : '';
      const members = flat.map(([name, value, written]) => `${stringText(name, false)}${gap}:${gap}${text(value, written)}`);
      members.push(`"user"${gap}:${gap}{${gap}` + nested.map(([name, value]) => `${stringText(name, false)}${gap}:${gap}${text(value, null)}`).join(`${gap},${gap}`) + `${gap}}`);
      if (options.reversed) members.reverse();
      return `{${gap}` + members.join(options.spaced ? ' ,\t' : ',') + `${gap}}`;
    };
    const add = (variant: string, raw: string, expect: JsonCase['expect']) => cases.push({
      id: `json-${seed}-${index}-${variant}`, raw, provenance: `model-rendered JSON object (${variant}); expectation is the meant value of every member`, expect,
    });
    const full: JsonCase['expect'] = { status: 'FULL', values: expectValues };
    const compact = render();
    add('compact', compact, full);
    add('insignificant-white-space', render({ spaced: true }), full);
    add('escaped-spelling', render({ escapeAll: true }), full);
    add('members-reversed', render({ reversed: true }), full);
    add('trailing-comma', compact.slice(0, -1) + ',}', { status: 'UNKNOWN' });
    add('single-quoted-name', "{'srcip':\"10.1.1.1\"," + compact.slice(1), { status: 'UNKNOWN' });
    add('bare-name', '{srcip2:1,' + compact.slice(1), { status: 'UNKNOWN' });
    add('truncated', compact.slice(0, -1), { status: 'UNKNOWN' });
    add('text-after-object', compact + ' trailing', { status: 'UNKNOWN' });
    add('leading-zero-number', compact.slice(0, -1) + ',"n":01}', { status: 'UNKNOWN' });
    add('nan-literal', compact.slice(0, -1) + ',"n":NaN}', { status: 'UNKNOWN' });
    add('repeated-name', compact.slice(0, -1) + ',"srcip":"again"}', { status: 'UNKNOWN' });
    add('integer-beyond-2-53', compact.slice(0, -1) + ',"big":12345678901234567890}', { status: 'FULL', neverWrong: true, values: expectValues, exactDigits: { big: '12345678901234567890' } });
  }
  return cases;
}
