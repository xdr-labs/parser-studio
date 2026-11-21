/**
 * Loss guard: pairs behind a list delimiter (Issue #315, Phase 3 P1).
 *
 * The key=value grammar separates pairs at SP and TAB only (contract KV_GAP), so it reads
 * "src=10.0.0.1,dst=10.0.0.2,action=allow" as ONE pair whose value is the rest of the line. The independent
 * reader of the Parsing Success Contract cut its tokens at white space as well, saw the same single pair, and
 * the event was reported FULL with two fields missing. Evidence that shares the grammar's idea of a separator
 * is not independent of it: the reader also sees a pair that starts behind a list delimiter (, ; |).
 */
import { describe, expect, it } from 'vitest';
import { classifyStructuredParse, independentKeyValuePairs } from './parseStatus';

const written = (raw: string) => independentKeyValuePairs(raw).map(pair => [pair.key, pair.rawValue]);
const THREE = [['src', '10.0.0.1'], ['dst', '10.0.0.2'], ['action', 'allow']];

describe('independent pair evidence behind a list delimiter', () => {
  it.each([',', ';', '|'])('sees every pair of a line whose pairs are separated by %j alone', delimiter => {
    expect(written(['src=10.0.0.1', 'dst=10.0.0.2', 'action=allow'].join(delimiter))).toEqual(THREE);
  });

  it('sees the pairs behind a Syslog header as well', () => {
    expect(written('<134>Nov 13 10:00:00 fw01 src=10.0.0.1,dst=10.0.0.2,action=allow')).toEqual(THREE);
  });

  it.each([', ', ';  ', '|\t'])('does not take the delimiter of %j into the value before it', separator => {
    expect(written(['src=10.0.0.1', 'dst=10.0.0.2', 'action=allow'].join(separator))).toEqual(THREE);
  });

  it('sees a pair behind a delimiter that follows a quoted value', () => {
    expect(written('a="x y",b=2;c=\'z=1\'|d=4, e="5"')).toEqual([['a', 'x y'], ['b', '2'], ['c', 'z=1'], ['d', '4'], ['e', '5']]);
  });

  it('keeps a value that is a list of pairs of its own whole (a distinguished name, a cookie)', () => {
    expect(written('dn=CN=John,OU=Users,DC=corp srcip=10.1.1.1 cookie=a=1;b=2'))
      .toEqual([['dn', 'CN=John,OU=Users,DC=corp'], ['srcip', '10.1.1.1'], ['cookie', 'a=1;b=2']]);
  });

  it('keeps a URL with a query string whole', () => {
    expect(written('url=http://x/?a=1,b=2 action=allow')).toEqual([['url', 'http://x/?a=1,b=2'], ['action', 'allow']]);
  });

  it('keeps a delimiter that no key follows as value data', () => {
    expect(written('list=a,b,c ports=1;2|3 note=x,=y last=1,')).toEqual([['list', 'a,b,c'], ['ports', '1;2|3'], ['note', 'x,=y'], ['last', '1,']]);
    expect(written('a=1, stray b=2')).toEqual([['a', '1,'], ['b', '2']]);
  });

  it('leaves white-space separated pairs exactly as before', () => {
    expect(written('src=10.0.0.1 dst=10.0.0.2\taction=allow')).toEqual(THREE);
  });
});

describe('Parsing Success Contract for a delimiter separated line', () => {
  const RAW = 'src=10.0.0.1,dst=10.0.0.2,action=allow';

  it('is not FULL when the grammar kept the whole line as the value of the first key', () => {
    const verdict = classifyStructuredParse(RAW, { fields: { src: '10.0.0.1,dst=10.0.0.2,action=allow' }, errors: [] }, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['src', 'dst', 'action']);
  });

  it('is not FULL when a value kept the delimiter that followed it', () => {
    const verdict = classifyStructuredParse('src=10.0.0.1, dst=10.0.0.2', { fields: { src: '10.0.0.1,', dst: '10.0.0.2' }, errors: [] }, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['src']);
  });

  it('is FULL when every pair is a field with its own value', () => {
    const verdict = classifyStructuredParse(RAW, { fields: { src: '10.0.0.1', dst: '10.0.0.2', action: 'allow' }, errors: [] }, 'kv');
    expect(verdict).toEqual({ status: 'FULL', lostPairs: [], reasons: [] });
  });
});
