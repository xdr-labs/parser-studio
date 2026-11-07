import {describe,expect,it} from 'vitest';
import {portableRegexIssue} from '../backend/src/portable-regex';
import {validatePreviewRegexPattern} from './regexSafety';

const bad=[
  String.raw`^(?<field>\A\d+)$`,
  String.raw`^(?<field>\d+\z)$`,
  String.raw`^(?<field>\h+)$`,
  String.raw`^(?<field>[\h]+)$`,
  String.raw`^(?<field>[[:digit:]]+)$`,
  String.raw`^(?<field>.*.*.*.*.*.*)b$`,
  String.raw`^(?<field>[ab]*[ab]*[ab]*[ab]*[ab]*)c$`,
  String.raw`^(?<field>a{0,128}a{0,128}a{0,128}a{0,128})b$`,
  String.raw`^(?<field>.*a.*a.*a.*a.*a.*)z$`,
];
const good=[
  String.raw`^action=(?<action>\w+)$`,
  String.raw`(?<field>tcp|udp)$`,
  String.raw`(?<field>[^\x22\x27\\]+)`,
  String.raw`^(?<month>\d{2})-(?<day>\d{2})\s+(?<name>\w+)$`,
  String.raw`^(?<field>\d+\s+)$`,
];

describe('single portable regex policy — browser',()=>{
  it.each(bad)('rejects an invalid dialect or ambiguous repetition: %s',pattern=>{
    expect(portableRegexIssue(pattern)).not.toBeNull();
    expect(validatePreviewRegexPattern(pattern)).toMatch(/unsupported|expensive/i);
  });
  it.each(good)('preserves supported common grammar: %s',pattern=>{
    expect(portableRegexIssue(pattern)).toBeNull();
    expect(validatePreviewRegexPattern(pattern)).toBeNull();
  });
});
