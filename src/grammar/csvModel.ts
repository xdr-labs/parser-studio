/**
 * Property-based case generator for delimiter-separated rows (CSV).
 *
 * A row is rendered from the values the sender MEANT. The expectation is those
 * values, never the result of parsing the rendered text.
 *
 * Wire rules used for rendering (RFC 4180 section 2, with the delimiter as a
 * parameter):
 *  - fields are separated by the delimiter;
 *  - a field may be enclosed in double quotes; a field that contains the
 *    delimiter or a double quote MUST be enclosed;
 *  - a double quote inside an enclosed field is written twice;
 *  - a double quote may not appear inside a field that is not enclosed.
 * A value that is not enclosed never begins or ends with white space: whether
 * a receiver keeps that white space is a product choice, so the model does not
 * claim an answer. An empty field is "no value"; an engine may report it as an
 * empty string or as absent.
 */
export interface CsvCase {
  id: string;
  delimiter: ',' | ';' | '\t';
  columns: number;
  raw: string;
  provenance: string;
  expect: { status: 'FULL' | 'UNKNOWN'; values?: string[]; rejected?: 'syntax' | 'column-count' };
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

const VALUES = ['allow', '10.1.1.1', '443', 'hello world', 'a,b', 'semi;colon', 'tab\there', 'say "hi" now', '"quoted"', ' padded ',
  'a\u2028b', 'a\u00a0b', '\uD55C\uAD6D\uC5B4 \uB85C\uADF8', 'C:\\dir\\f', 'k=v', "it's", '', '0', 'x'];
export const CSV_MODEL_COLUMNS = 5;

const mustEnclose = (value: string, delimiter: string) =>
  value.includes(delimiter) || value.includes('"') || /^[ \t]|[ \t]$/.test(value) || value.includes('\t');
const enclosed = (value: string) => '"' + value.split('"').join('""') + '"';

export function generateCsvCases(count: number, seed: number): CsvCase[] {
  const random = mulberry32(seed);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const cases: CsvCase[] = [];
  for (let index = 0; index < count; index += 1) {
    const delimiter = ([',', ';', '\t'] as const)[index % 3]!;
    const values = Array.from({ length: CSV_MODEL_COLUMNS }, () => pick(VALUES));
    // A row needs at least one visible value in its first field so that it is not an empty line.
    if (values[0] === '') values[0] = 'allow';
    const minimal = values.map(value => (mustEnclose(value, delimiter) ? enclosed(value) : value));
    const add = (variant: string, fields: string[], expect: CsvCase['expect']) => cases.push({
      id: `csv-${seed}-${index}-${variant}`, delimiter, columns: CSV_MODEL_COLUMNS, raw: fields.join(delimiter),
      provenance: `model-rendered row (${variant}); expectation is the meant value of every field`, expect,
    });
    add('minimal-quoting', minimal, { status: 'FULL', values });
    add('every-field-enclosed', values.map(enclosed), { status: 'FULL', values });
    add('quote-never-closed', [...minimal.slice(0, -1), '"open'], { status: 'UNKNOWN', rejected: 'syntax' });
    add('quote-inside-bare-field', [...minimal.slice(0, -1), 'ab"cd'], { status: 'UNKNOWN', rejected: 'syntax' });
    add('text-after-closing-quote', [...minimal.slice(0, -1), '"ab"cd'], { status: 'UNKNOWN', rejected: 'syntax' });
    add('one-field-missing', minimal.slice(0, -1), { status: 'UNKNOWN', rejected: 'column-count' });
    add('one-field-extra', [...minimal, 'extra'], { status: 'UNKNOWN', rejected: 'column-count' });
  }
  return cases;
}
