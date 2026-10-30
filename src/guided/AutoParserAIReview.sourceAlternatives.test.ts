import {describe,expect,it} from 'vitest';
import {sourceAlternatives} from './AutoParserAIReview';

// The browser key=value reader decodes backslash escapes (strictKeyValues: `\=` -> `=`),
// while the backend span evidence keeps the raw source text.
describe('source value alternatives for the reviewed-value gate',()=>{
 it('accepts the decoded form of a backslash-escaped key=value',()=>{
  expect(sourceAlternatives('Request-Content-Type=text/plain;charset\\=UTF-8'))
   .toContain('Request-Content-Type=text/plain;charset=UTF-8');
 });
 it('keeps the exact source text as an alternative',()=>{
  expect(sourceAlternatives('a\\=b')).toContain('a\\=b');
 });
 it('adds nothing for values without a backslash',()=>{
  expect(sourceAlternatives('plain')).toEqual(['plain']);
 });
});
