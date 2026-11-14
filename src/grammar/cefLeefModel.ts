/**
 * Property-based case generator for standalone CEF and LEEF events.
 *
 * A case is rendered from a model: header fields and extension pairs, each with
 * the value the sender MEANT and the text that the format's escaping rules
 * require on the wire. The expectation is the meant value, never the result of
 * parsing the rendered text.
 *
 * Wire rules used for rendering (and nothing else):
 *  - CEF header: "|" is written "\|" and "\" is written "\\"; "=" is literal.
 *  - CEF extension: pairs are separated by one SP; in a value "=" is written
 *    "\=", "\" is written "\\" and a line feed is written "\n"; "|" is literal.
 *  - CEF needs seven header fields, each followed by "|".
 *  - LEEF 1.0 separates attributes with TAB; LEEF 2.0 names the separator in a
 *    sixth header field. A value runs to the next separator; the first "=" of
 *    an attribute ends the key.
 * Values never begin or end with white space and never contain an unescaped
 * " key=" sequence: what a receiver should do with those is not stated by the
 * formats, so the model does not claim an answer.
 */
export interface FamilyExpectation {
  status: 'FULL' | 'UNKNOWN';
  /** FULL only: the engine may decline the line, but must never report a different value. */
  neverWrong?: boolean;
  header?: Record<string, string>;
  extension?: Record<string, string>;
  /** Owner policy D-1, UNKNOWN only: fields written more than once, with every meant value in wire order. */
  repeated?: Record<string, string[]>;
}
export interface FamilyCase { id: string; family: 'cef' | 'leef'; raw: string; provenance: string; expect: FamilyExpectation }

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

const cefHeaderText = (meant: string) => meant.split('\\').join('\\\\').split('|').join('\\|');
const cefValueText = (meant: string) => meant.split('\\').join('\\\\').split('=').join('\\=').split('\n').join('\\n');

const CEF_HEADER: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['cef_device_vendor', ['Acme', 'Trend Micro', 'A|B Corp', 'Back\\Slash']],
  ['cef_device_product', ['FW', 'Deep Security', 'Fire|wall']],
  ['cef_device_version', ['1.0', '7.2.1']],
  ['cef_signature_id', ['100', '4000000', 'traffic:forward']],
  ['cef_name', ['Blocked flow', 'Log=in attempt', 'Path C:\\x', '\uD55C\uAD6D\uC5B4 \uC774\uBCA4\uD2B8']],
  ['cef_severity', ['5', '10', 'High']],
];
const TEXT_VALUES = ['hello world', 'a=b', 'C:\\dir\\f', 'C:\\Users\\new\\report', '\\\\server\\reports', 'ends with a backslash\\', 'line1\nline2', 'pipe|inside', 'a\u2028b', 'a\u00a0b', '\uD55C\uAD6D\uC5B4 \uB85C\uADF8', 'x y z', 'http://x/?a=b&c=d'];
const CEF_EXTENSION: Readonly<Record<string, readonly string[]>> = {
  src: ['10.1.1.1', '192.168.0.254'], dst: ['10.2.2.2', '8.8.8.8'], spt: ['1234', '65535'], dpt: ['443', '22'],
  act: ['deny', 'accept'], suser: ['alice', 'user@example.com'], msg: TEXT_VALUES, cs1: TEXT_VALUES, request: TEXT_VALUES,
};
const LEEF_HEADER: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['leef_vendor', ['Acme', 'IBM']], ['leef_product', ['FW', 'QRadar Sim']], ['leef_product_version', ['1.0', '7.2.1']], ['leef_event_id', ['100', 'Logon_Failure']],
];
// LEEF has no escaping: a value is literal up to the next separator, so no value contains TAB or "^".
const LEEF_TEXT = ['hello world', 'a=b', 'C:\\dir\\f', '\\\\server\\share', 'C:\\dir\\', 'pipe|inside', 'a\u2028b', '\uD55C\uAD6D\uC5B4 \uB85C\uADF8', 'http://x/?a=b&c=d'];
const LEEF_ATTRIBUTES: Readonly<Record<string, readonly string[]>> = {
  src: ['10.1.1.1', '192.168.0.254'], dst: ['10.2.2.2', '8.8.8.8'], srcPort: ['1234'], dstPort: ['443'],
  usrName: ['alice'], msg: LEEF_TEXT, reason: LEEF_TEXT,
};

const UNKNOWN: FamilyExpectation = { status: 'UNKNOWN' };

export function generateCefLeefCases(count: number, seed: number): FamilyCase[] {
  const random = mulberry32(seed);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const some = (pool: Readonly<Record<string, readonly string[]>>): Array<[string, string]> =>
    Object.keys(pool).sort(() => random() - 0.5).slice(0, 2 + Math.floor(random() * 5)).map(key => [key, pick(pool[key]!)]);
  const cases: FamilyCase[] = [];
  for (let index = 0; index < count; index += 1) {
    // ------------------------------------------------------------------ CEF
    const header = CEF_HEADER.map(([name, pool]) => [name, pick(pool)] as [string, string]);
    const pairs = some(CEF_EXTENSION);
    const headerText = 'CEF:0|' + header.map(([, meant]) => cefHeaderText(meant)).join('|') + '|';
    const extensionText = (list: Array<[string, string]>) => list.map(([key, meant]) => key + '=' + cefValueText(meant)).join(' ');
    const cef = (variant: string, raw: string, expect: FamilyExpectation) => cases.push({
      id: `cef-${seed}-${index}-${variant}`, family: 'cef', raw,
      provenance: `model-rendered CEF (${variant}); expectation is the meant value of every header field and extension pair`, expect,
    });
    const cefFull = (list: Array<[string, string]>): FamilyExpectation =>
      ({ status: 'FULL', header: { cef_version: '0', ...Object.fromEntries(header) }, extension: Object.fromEntries(list) });
    cef('base', headerText + extensionText(pairs), cefFull(pairs));
    cef('reversed', headerText + extensionText([...pairs].reverse()), cefFull([...pairs].reverse()));
    // Six "|" after "CEF:0": the seventh header field is not terminated, so this is not a CEF event.
    cef('severity-field-missing', 'CEF:0|' + header.slice(0, 5).map(([, meant]) => cefHeaderText(meant)).join('|') + '|' + extensionText(pairs), UNKNOWN);
    // A backslash at the very end escapes nothing.
    cef('escape-truncated', headerText + extensionText(pairs) + ' cs2=tail\\', UNKNOWN);
    // Owner policy D-1: the first field is written again at the end with another value.
    const again = (list: Array<[string, string]>): FamilyExpectation => ({ status: 'UNKNOWN', repeated: { [list[0]![0]]: [list[0]![1], 'again'] } });
    cef('duplicate-field', headerText + extensionText([...pairs, [pairs[0]![0], 'again']]), again(pairs));

    // ----------------------------------------------------------------- LEEF
    const leefHeader = LEEF_HEADER.map(([name, pool]) => [name, pick(pool)] as [string, string]);
    const attributes = some(LEEF_ATTRIBUTES);
    const leef = (variant: string, raw: string, expect: FamilyExpectation) => cases.push({
      id: `leef-${seed}-${index}-${variant}`, family: 'leef', raw,
      provenance: `model-rendered LEEF (${variant}); expectation is the meant value of every header field and attribute`, expect,
    });
    const leefFull = (version: string, list: Array<[string, string]>, neverWrong = false): FamilyExpectation =>
      ({ status: 'FULL', ...(neverWrong ? { neverWrong } : {}), header: { leef_version: version, ...Object.fromEntries(leefHeader) }, extension: Object.fromEntries(list) });
    const head = (version: string) => `LEEF:${version}|` + leefHeader.map(([, meant]) => meant).join('|') + '|';
    const body = (list: Array<[string, string]>, separator: string) => list.map(([key, meant]) => key + '=' + meant).join(separator);
    leef('v1-tab', head('1.0') + body(attributes, '\t'), leefFull('1.0', attributes));
    leef('v1-tab-reversed', head('1.0') + body([...attributes].reverse(), '\t'), leefFull('1.0', [...attributes].reverse()));
    leef('v2-caret', head('2.0') + '^|' + body(attributes, '^'), leefFull('2.0', attributes));
    // The hexadecimal spelling of the separator is allowed by LEEF 2.0; an engine may decline it but must not misread it.
    leef('v2-hex-tab', head('2.0') + 'x09|' + body(attributes, '\t'), leefFull('2.0', attributes, true));
    leef('version-3', head('3.0') + body(attributes, '\t'), UNKNOWN);
    leef('v1-duplicate-field', head('1.0') + body([...attributes, [attributes[0]![0], 'again']], '\t'), again(attributes));
    leef('v2-duplicate-field', head('2.0') + '^|' + body([...attributes, [attributes[0]![0], 'again']], '^'), again(attributes));
  }
  return cases;
}
