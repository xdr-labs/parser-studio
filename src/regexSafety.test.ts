import { describe, expect, it } from 'vitest';
import { validatePreviewRegexPattern } from './regexSafety';
import { createFieldProposal } from './pattern';

describe('bounded, browser-only regular expression safety gate', () => {
  it.each([
    '(?<x>(a|aa)+)$',
    '(?<x>(?:a|aa)+)$',
    '(?<x>(a+)+)$',
    '(?<x>(a?){25})$',
    '(?<x>a*a*)$',
    '(?<x>a{100000})$',
    '(?<x>(a|b){999})$',
    '(?<x>\\1(a)+)$',
    '(?<x>(?<=a)b)$',
  ])('refuses known exponentially expensive or unsupported pattern syntax: %s', (pattern) => {
    const error = validatePreviewRegexPattern(pattern);
    expect(error).toMatch(/unsupported|expensive/i);
  });

  it('keeps simple explicit bounded named-group captures allowed', () => {
    expect(validatePreviewRegexPattern('^action=(?<action>\\w+)$')).toBeNull();
    expect(validatePreviewRegexPattern('(?<code>[A-Z]{2,6})')).toBeNull();
    expect(validatePreviewRegexPattern('(?<action>[^\\s,;}]+)')).toBeNull();
  });

  it('accepts generated visual field proposals while never persisting example value', () => {
    const result = createFieldProposal('action=deny src_ip=198.51.100.10', 'deny', 'action');
    expect('error' in result).toBe(false);
    if ('error' in result) return;
    expect(validatePreviewRegexPattern(result.pattern)).toBeNull();
    expect(result.pattern).not.toContain('deny');
  });

  it('enforces a finite maximum pattern length and named captures', () => {
    expect(validatePreviewRegexPattern('(?<x>'+'a'.repeat(300)+')')).toContain('256');
    expect(validatePreviewRegexPattern('a+')).toContain('named');
    expect(validatePreviewRegexPattern('')).toBeTruthy();
  });
});
