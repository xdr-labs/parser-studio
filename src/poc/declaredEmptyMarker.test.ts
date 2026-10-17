import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {inspectDeclaredEmptyMarker,type EmptyMarkerProfile} from './declaredEmptyMarker';

const documentSha='b9ef7ca4e86f416415fa9c850fd738376f59a2808fa8f3ea289d3270a4d9bcd8';
const original='Feb  2 16:00:55 relay-host eve_type="system" eve_status=% eve_profile=% eve_msg="é ok"';
const make=(raw:string,fields=['eve_type','eve_status','eve_profile','eve_msg']):EmptyMarkerProfile=>({
 framing:'INDEPENDENTLY_DOCUMENTED_RFC3164_KV_CUSTOM_FORMAT',
 valueContract:'EXPLICIT_UNQUOTED_EMPTY_MARKER',
 sourceSha256:createHash('sha256').update(raw,'utf8').digest('hex'),
 manufacturerDocSha256:documentSha,emptyMarker:'%',declaredKeys:fields,
});
describe('isolated publisher-documented custom empty marker',()=>{
 it('distinguishes present-but-empty from populated source lexemes',()=>{
  const found=inspectDeclaredEmptyMarker(original,make(original));
  expect(found.disposition).toBe('REVIEW_ONLY');
  expect(found.fields.find(x=>x.name==='eve_status')?.state)
   .toBe('PRESENT_EMPTY_DOCUMENTED');
  expect(found.fields.find(x=>x.name==='eve_profile')?.state)
   .toBe('PRESENT_EMPTY_DOCUMENTED');
  expect(found.fields.find(x=>x.name==='eve_type')?.state)
   .toBe('PRESENT_NONEMPTY_LEXICAL');
  expect(found.fields.find(x=>x.name==='eve_msg')?.state)
   .toBe('PRESENT_NONEMPTY_LEXICAL');
  expect(found.raw).toBe(original);
  expect(found.autoPromoted).toBe(false);
  expect(found.manufacturerFirmwareWire).toBe('NOT_VERIFIED');
  expect(found.nativeStellar).toBe('NOT_VERIFIED');
  expect(found.branchAttempts).toBeLessThanOrEqual(2);
  expect(found.maxDepth).toBe(1);
 });
 it('preserves every original byte and precise Unicode UTF-8 value offsets',()=>{
  const found=inspectDeclaredEmptyMarker(original,make(original));
  const bytes=Buffer.from(original,'utf8');
  expect(found.sourceBytes).toBe(bytes.length);
  for(const field of found.fields){
   expect(bytes.subarray(field.valueStartByte,field.valueEndByte).toString('utf8'))
    .toBe(field.sourceLexeme);
   expect(bytes.subarray(field.nameStartByte,field.nameEndByte).toString('utf8'))
    .toBe(field.name);
  }
 });
 it('does not infer empty meanings from lexical percent without a source profile',()=>{
  const found=inspectDeclaredEmptyMarker(original);
  expect(found.disposition).toBe('RAW_ONLY');
  expect(found.fields).toEqual([]);
  expect(found.emptyMarkerSemantics).toBe('NOT_CERTIFIED');
 });
 it('treats missing fields as absent, never as present empty',()=>{
  const raw=original.replace(' eve_profile=%','');
  const found=inspectDeclaredEmptyMarker(raw,make(raw));
  expect(found.disposition).toBe('REVIEW_ONLY');
  expect(found.absentKeys).toContain('eve_profile');
  expect(found.fields.find(f=>f.name==='eve_profile')).toBeUndefined();
 });
 it('keeps quoted percent and quoted empty as UNSCORABLE rather than sentinel values',()=>{
  for(const lex of ['"%"','""']){
   const raw=original.replace('eve_profile=%','eve_profile='+lex);
   const result=inspectDeclaredEmptyMarker(raw,make(raw));
   expect(result.disposition).toBe('REVIEW_ONLY');
   expect(result.fields.find(f=>f.name==='eve_profile')?.state)
    .toBe('PRESENT_VALUE_UNSCORABLE');
   expect(result.fields.find(f=>f.name==='eve_status')?.state)
    .toBe('PRESENT_EMPTY_DOCUMENTED');
  }
 });
 it('fails closed on profile drift, malformed input or incompatible transport',()=>{
  for(const mutated of [
   original.replace('relay-host','relay-other'),
   original+'\\n<13>other',
   original.replace('16:00:55','29:00:55'),
   original+'X'.repeat(9000),
   original.replace('eve_type','bad=val eve_type'),
   original.replace('eve_type','eve_profile'),
  ]){
   const decision=inspectDeclaredEmptyMarker(mutated,make(original));
   expect(decision.disposition).toBe('ABSTAIN_UNSAFE');
   expect(decision.fields).toEqual([]);
  }
  const rfc5424='<34>1 2026-01-01T12:00:00Z host app - id - a=%';
  const decision=inspectDeclaredEmptyMarker(rfc5424,make(rfc5424,['a']));
  expect(decision.disposition).toBe('ABSTAIN_UNSAFE');
 });
 it('rejects unsafe or conflicting declared schemas and reserved symbols',()=>{
  const profiles=[
   {...make(original),emptyMarker:'a'},
   {...make(original),emptyMarker:'='},
   {...make(original),emptyMarker:' '},
   {...make(original),emptyMarker:'\\'},
   {...make(original),declaredKeys:['eve_type','eve_type']},
   {...make(original),declaredKeys:['__proto__']},
   {...make(original),sourceSha256:'0'.repeat(64)},
   {...make(original),manufacturerDocSha256:'not-a-sha'},
  ];
  for(const profile of profiles){
   const out=inspectDeclaredEmptyMarker(original,profile as EmptyMarkerProfile);
   expect(out.disposition).toBe('ABSTAIN_UNSAFE');
   expect(out.fields).toEqual([]);
  }
 });
 it('requires explicit manufacturer source evidence even with parseable bare KV',()=>{
  const raw='type=foo state=%';
  const result=inspectDeclaredEmptyMarker(raw,make(raw,['type','state']));
  expect(result.disposition).toBe('ABSTAIN_UNSAFE');
  expect(result.fields).toEqual([]);
 });
 it('rejects manufacturer-unknown escape semantics, not guessed decoding',()=>{
  const raw=original.replace('eve_msg="é ok"','eve_msg="foo\\qbar"');
  const out=inspectDeclaredEmptyMarker(raw,make(raw));
  expect(out.disposition).toBe('ABSTAIN_UNSAFE');
  expect(out.fields).toEqual([]);
 });
});
