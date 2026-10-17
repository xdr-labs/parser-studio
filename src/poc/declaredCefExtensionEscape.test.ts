import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {inspectDeclaredCefEscape,type DeclaredCefEscapeProfile}
 from './declaredCefExtensionEscape';

const doc='d4085e6f7363887a88cff469837828ecaebb6647722dbb5eef8cb82d90987a40';
const raw='Dec 27 11:20:48 relay-fw CEF: 0|Example|Gateway|1.0|event|threat detected|4|cs1=http://example.test/x?q\\=1 act=blocked';
const profile=(source:string,key='cs1'):DeclaredCefEscapeProfile=>({
 framing:'INDEPENDENTLY_DOCUMENTED_SINGLE_CEF_RECORD',
 valueGrammar:'BACKSLASH_ESCAPES_EQUALS',
 sourceSha256:createHash('sha256').update(source,'utf8').digest('hex'),
 manufacturerDocumentSha256:doc,sourceFieldName:key,
});

describe('independently declared CEF literal backslash-equals escape source observer',()=>{
 it('recovers exactly the declared escaped extension field without altering bytes',()=>{
  const out=inspectDeclaredCefEscape(raw,profile(raw));
  expect(out.disposition).toBe('REVIEW_ONLY');
  expect(out.fields).toHaveLength(1);
  const field=out.fields[0]!;
  expect(field.sourceFieldName).toBe('cs1');
  expect(field.rawLexeme).toBe('http://example.test/x?q\\=1');
  expect(field.decodedValue).toBe('http://example.test/x?q=1');
  expect(field.escapeCount).toBe(1);
  expect(out.raw).toBe(raw);
  expect(out.autoPromoted).toBe(false);
  expect(out.firmwareWire).toBe('NOT_VERIFIED');
  expect(out.nativeStellar).toBe('NOT_VERIFIED');
  expect(out.branchAttempts).toBeLessThanOrEqual(2);
  expect(out.maxDepth).toBe(1);
 });
 it('preserves exact full-original UTF-8 value offsets for the encoded source literal',()=>{
  const changed=raw.replace('http://example.test','https://exämple.test');
  const out=inspectDeclaredCefEscape(changed,profile(changed));
  expect(out.disposition).toBe('REVIEW_ONLY');
  const field=out.fields[0]!;
  const bytes=Buffer.from(changed,'utf8');
  expect(out.sourceBytes).toBe(bytes.length);
  expect(bytes.subarray(field.keyStartByte,field.keyEndByte).toString('utf8'))
   .toBe(field.sourceFieldName);
  expect(bytes.subarray(field.valueStartByte,field.valueEndByte).toString('utf8'))
   .toBe(field.rawLexeme);
  expect(field.decodedValue).toContain('exämple');
 });
 it('refuses to infer vendor CEF escapes without independently supplied profile',()=>{
  const result=inspectDeclaredCefEscape(raw);
  expect(result.disposition).toBe('RAW_ONLY');
  expect(result.fields).toEqual([]);
 });
 it('requires exact source SHA and a well-formed evidence profile',()=>{
  for(const declared of [
   {...profile(raw),sourceSha256:'0'.repeat(64)},
   {...profile(raw),manufacturerDocumentSha256:'not-a-sha'},
   {...profile(raw),sourceFieldName:'__proto__'},
   {...profile(raw),sourceFieldName:'[invalid]'},
  ]){
   const out=inspectDeclaredCefEscape(raw,declared);
   expect(out.disposition).toBe('ABSTAIN_UNSAFE');
   expect(out.fields).toEqual([]);
  }
 });
 it('rejects ambiguous, absent or repeated extension fields',()=>{
  for(const changed of [
   raw.replace('cs1=','cs2='),
   raw.replace(' act=blocked',' cs1=q\\=2 act=blocked'),
   raw.replace('q\\=1','q=1'),
   raw.replace('q\\=1','q\\q1'),
   raw.replace('q\\=1','q"\\=1'),
  ]){
   const out=inspectDeclaredCefEscape(changed,profile(changed));
   expect(out.disposition).toBe('ABSTAIN_UNSAFE');
   expect(out.fields).toEqual([]);
  }
 });
 it('accepts the same declared format without an RFC3164 header',()=>{
  const changed=raw.slice(raw.indexOf('CEF:'));
  const out=inspectDeclaredCefEscape(changed,profile(changed));
  expect(out.disposition).toBe('REVIEW_ONLY');
  expect(out.fields[0]?.decodedValue).toBe('http://example.test/x?q=1');
 });
 it('abstains on malformed headers, multiline transports and oversized messages',()=>{
  for(const bad of [
   raw.replace('11:20:48','99:20:48'),
   raw.replace('0|Example','999|Example'),
   raw.replace('|4|cs1','4|cs1'),
   raw.replace('CEF: 0','CEF: xxx'),
   raw+'\nCEF:0|repeat|',
   raw+'A'.repeat(9000),
  ]){
   const out=inspectDeclaredCefEscape(bad,profile(bad));
   expect(out.disposition).toBe('ABSTAIN_UNSAFE');
   expect(out.fields).toEqual([]);
  }
 });
 it('remains a bounded optional generic decoder with no vendor-name selection',()=>{
  const changed=raw.replace('cs1=','target_file=').replace('Example|Gateway','Other|Sensor');
  const out=inspectDeclaredCefEscape(changed,profile(changed,'target_file'));
  expect(out.disposition).toBe('REVIEW_ONLY');
  expect(out.fields[0]?.sourceFieldName).toBe('target_file');
 });
 it('does not guess CEF escaped pipe, newline or backslash sequences',()=>{
  for(const suffix of ['\\|','\\n','\\\\']){
   const changed=raw.replace('q\\=1','q\\=1'+suffix);
   const out=inspectDeclaredCefEscape(changed,profile(changed));
   expect(out.disposition).toBe('ABSTAIN_UNSAFE');
   expect(out.fields).toEqual([]);
  }
 });
});
