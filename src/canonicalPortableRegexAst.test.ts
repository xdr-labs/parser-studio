import {describe,expect,it} from 'vitest';
import {parsePortableRegexAst,portableRegexIssue} from '../backend/src/portable-regex';
import {validatePreviewRegexPattern} from './regexSafety';

describe('H1 portable regex AST contract',()=>{
  it('retains captures, alternations, bounded counts and literal escapes',()=>{
    const pattern=String.raw`^(?<month>\d{2})/(?<action>allow|deny)\s+(?<quoted>[^\x22\\]+)$`;
    const result=parsePortableRegexAst(pattern);
    expect(result).toMatchObject({ok:true,captureNames:['month','action','quoted']});
    if(!result.ok)return;
    expect(result.ast.kind).toBe('sequence');
    expect(JSON.stringify(result.ast)).toContain('"min":2');
    expect(JSON.stringify(result.ast)).toContain('"kind":"alternation"');
  });
  it.each([
    String.raw`(?=allow)(?<action>allow)`,
    String.raw`(?!deny)(?<action>allow)`,
    String.raw`(?i:(?<action>allow))`,
    String.raw`(?<field>\p{Letter}+)`,
    String.raw`(?<field>a{3,129})`,
    String.raw`(?<field>foo`+'\\',
  ])('rejects unsupported dialect, unsafe bounds or invalid structure: %s',(pattern)=>{
    expect(portableRegexIssue(pattern)).not.toBeNull();
    expect(validatePreviewRegexPattern(pattern)).toMatch(/unsupported|expensive|named/i);
  });
  it('never counts a fake capture inside a character class or escaped literal',()=>{
    const escaped=String.raw`\(\?<fake>foo\)`;
    expect(parsePortableRegexAst(escaped)).toMatchObject({ok:true,captureNames:[]});
    expect(validatePreviewRegexPattern(escaped)).toContain('named');
  });
});
