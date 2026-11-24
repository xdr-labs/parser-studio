/**
 * Delimited list of key=value pairs (Issue #315, Phase 3 P1).
 *
 * A body whose pairs are separated by ONE list delimiter (, ; |) - optionally followed by SP or TAB - is read
 * as its pairs: "src=10.0.0.1,dst=10.0.0.2,action=allow" is three fields. Everything else is the white space
 * grammar's, exactly as before: one pair, pairs separated by white space, two different delimiters, and a value
 * that is a list of its own (a distinguished name "CN=a,OU=b").
 */
import { describe, expect, it } from 'vitest';
import { parseStrictKeyValues } from './kvBody';
import { preview } from '../parser';
import { createDraft } from '../model';

const pairs = (input: string) => { const body = parseStrictKeyValues(input); return body.ok ? body.pairs : body.reason; };
const THREE = [['src', '10.0.0.1'], ['dst', '10.0.0.2'], ['action', 'allow']];

describe('key=value pairs separated by a list delimiter', () => {
  it.each([',', ';', '|', ', ', ';\t', '|  '])('reads every pair of a body separated by %j', separator => {
    expect(pairs(['src=10.0.0.1', 'dst=10.0.0.2', 'action=allow'].join(separator))).toEqual(THREE);
    expect(pairs(' ' + ['src=10.0.0.1', 'dst=10.0.0.2', 'action=allow'].join(separator) + ' \t')).toEqual(THREE);
  });

  it('reads a quoted value as the text between its quotes: nothing is decoded', () => {
    expect(pairs('msg="a, b=c",user=\'x y\',note="a\\=b",unc="\\\\srv\\share",path=C:\\Temp')).toEqual(
      [['msg', 'a, b=c'], ['user', 'x y'], ['note', 'a\\=b'], ['unc', '\\\\srv\\share'], ['path', 'C:\\Temp']]);
  });

  it('is not a list when a quoted value would need its own quote', () => {
    // The white space grammar reads the first pair with its escape and then finds no pair: declined, not guessed.
    expect(pairs('q="say \\"hi\\"",user="bob"')).toBe('MALFORMED_PAIR');
  });

  it('keeps Unicode white space and other characters as value data', () => {
    expect(pairs('note=a\u2028b,name=\uD55C\uAD6D\uC5B4,url=http://h/p:8080')).toEqual(
      [['note', 'a\u2028b'], ['name', '\uD55C\uAD6D\uC5B4'], ['url', 'http://h/p:8080']]);
  });

  it('leaves a body that is not one delimited list to the white space grammar', () => {
    expect(pairs('list=a,b,c')).toEqual([['list', 'a,b,c']]);
    expect(pairs('dn=CN=John,OU=Users,DC=corp')).toEqual([['dn', 'CN=John,OU=Users,DC=corp']]);
    expect(pairs('url=http://x/?a=1,b=2')).toEqual([['url', 'http://x/?a=1,b=2']]);
    expect(pairs('a=1 b=2,c=3')).toEqual([['a', '1'], ['b', '2,c=3']]);
    expect(pairs('a=1,b=2;c=3')).toEqual([['a', '1,b=2;c=3']]);
    expect(pairs('a=1,b=2,')).toEqual([['a', '1,b=2,']]);
    expect(pairs('a=1,,b=2')).toEqual([['a', '1,,b=2']]);
    expect(pairs('a=1 b=2\tc=3')).toEqual([['a', '1'], ['b', '2'], ['c', '3']]);
  });

  it('declines a list under the same rules as any key=value body', () => {
    expect(pairs('a=1,b=2,a=3')).toBe('DUPLICATE_KEY');
    // G-5: a reserved name is read under its reversible field name, in a list too.
    expect(pairs('a=1,__proto__=2')).toEqual([['a', '1'], ['parserstudio_key___proto__', '2']]);
    expect(pairs(Array.from({ length: 100 }, (_unused, at) => 'f' + at + '=' + at).join(','))).toHaveLength(100);
    expect(pairs(Array.from({ length: 101 }, (_unused, at) => 'f' + at + '=' + at).join(','))).toBe('TOO_MANY_PAIRS');
  });
});

describe('a delimited line in the preview pipeline', () => {
  const auto = () => ({ ...createDraft(), format: 'auto' as const });

  it.each(['src=10.0.0.1,dst=10.0.0.2,action=allow', 'src=10.0.0.1, dst=10.0.0.2, action=allow', 'src=10.0.0.1;dst=10.0.0.2;action=allow'])(
    'reads %j completely', raw => {
      const event = preview(raw, auto()).events[0]!;
      expect(event.fields).toEqual({ src: '10.0.0.1', dst: '10.0.0.2', action: 'allow' });
      expect(event.parseStatus).toBe('FULL');
      expect(event.raw).toBe(raw);
    });

  it('reads a delimited message behind a Syslog header completely', () => {
    const event = preview('<134>Nov 13 10:00:00 fw01 src=10.0.0.1,dst=10.0.0.2,action=allow', auto()).events[0]!;
    expect((event.fields as { body?: unknown }).body).toEqual({ src: '10.0.0.1', dst: '10.0.0.2', action: 'allow' });
    expect(event.parseStatus).toBe('FULL');
  });

  it('does not report a line with two different delimiters as completely read', () => {
    const event = preview('a=1,b=2;c=3', auto()).events[0]!;
    expect(event.parseStatus).not.toBe('FULL');
    expect(event.diagnostics.some(item => item.code === 'FIELD_LOSS_NOT_FULL')).toBe(true);
  });
});
