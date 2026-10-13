import {describe,it,expect} from 'vitest';
import {reviewLogicalBoundaries} from './logicalBoundaryReview';

describe('P0-AP1 bounded logical event boundary review (no native multiline claims)',()=>{
 it('groups separate pretty JSON objects with nested braces and quotes without losing physical lines',()=>{
  const sample=[
   '{',
   '  "user":"PRIVATE_USER",',
   '  "detail": {"text": "brace } in string"},',
   '  "action":"deny"',
   '}',
   '{',
   '  "action":"allow",',
   '  "src_ip":"198.51.100.10"',
   '}',
  ].join('\n');
  const report=reviewLogicalBoundaries(sample);
  expect(report).toMatchObject({contract:'auto-parser.logical-boundary-review.v0.1',
    status:'REVIEWABLE_MULTILINE',sourceLines:9,nonEmptyLines:9,
    accountedNonEmptyLines:9,multilineEventCount:2,ambiguousCount:0,
    nativeVerified:false,targetVerified:false,sourceIncluded:false});
  expect(report.groups.map(x=>({kind:x.kind,firstLine:x.firstLine,lastLine:x.lastLine,
    physicalLines:x.physicalLines}))).toEqual([
    {kind:'JSON_OBJECT',firstLine:1,lastLine:5,physicalLines:5},
    {kind:'JSON_OBJECT',firstLine:6,lastLine:9,physicalLines:4},
  ]);
  for(const secret of ['PRIVATE_USER','198.51.100.10','action','deny','brace }'])
    expect(JSON.stringify(report)).not.toContain(secret);
 });
 it('identifies bounded Java stack traces without claiming they are RFC3164 or compiled',()=>{
  const text=[
   '2026-10-13 12:12:12 ERROR com.demo.Service - PRIVATE_OWNER error',
   'java.lang.IllegalStateException: PRIVATE_SECRET',
   '    at com.demo.Service.run(Service.java:38)',
   'Caused by: java.lang.Exception: synthetic',
   '    at com.demo.Main.main(Main.java:12)',
  ].join('\n');
  const report=reviewLogicalBoundaries(text);
  expect(report).toMatchObject({status:'REVIEWABLE_MULTILINE',
   sourceLines:5,nonEmptyLines:5,accountedNonEmptyLines:5,
   multilineEventCount:1,ambiguousCount:0});
  expect(report.groups[0]).toMatchObject({kind:'JAVA_STACK',firstLine:1,
   lastLine:5,physicalLines:5});
  expect(JSON.stringify(report)).not.toContain('PRIVATE_SECRET');
  expect(JSON.stringify(report)).not.toContain('Service.run');
 });
 it('preserves an ambiguous/truncated JSON boundary as review-required, not success',()=>{
  const raw='{\n "src_ip":"198.51.100.10"\n';
  const result=reviewLogicalBoundaries(raw);
  expect(result).toMatchObject({status:'REVIEW_REQUIRED',ambiguousCount:1,
   sourceLines:3,nonEmptyLines:2,accountedNonEmptyLines:2,multilineEventCount:0});
  expect(JSON.stringify(result)).not.toContain('198.51.100.10');
 });
 it('counts orphan stack continuation separately and reports source line origins',()=>{
  const raw=[
   '    at com.unknown.Stack.run(Unknown.java:10)',
   '{',
   ' "action":"allow"',
   '}',
   'CUSTOMER_UNRECOGNIZED sensitive detail',
  ].join('\n');
  const result=reviewLogicalBoundaries(raw);
  expect(result).toMatchObject({status:'REVIEW_REQUIRED',
    sourceLines:5,nonEmptyLines:5,accountedNonEmptyLines:5,
    multilineEventCount:1,ambiguousCount:2});
  expect(result.groups.map(x=>x.firstLine)).toEqual([1,2,5]);
  expect(JSON.stringify(result)).not.toContain('CUSTOMER_UNRECOGNIZED');
 });
 it('returns no multiline claim for ordinary JSON Lines or blank input',()=>{
  const result=reviewLogicalBoundaries('{"action":"allow"}\n{"action":"deny"}');
  expect(result).toMatchObject({status:'NO_MULTILINE',sourceLines:2,
    multilineEventCount:0,ambiguousCount:0});
  expect(reviewLogicalBoundaries(' \n ')).toMatchObject({status:'NO_SAMPLES',
    multilineEventCount:0,ambiguousCount:0,sourceIncluded:false});
 });
 it('rejects oversized input, unbounded JSON depth and 500+ events',()=>{
  const oversized=reviewLogicalBoundaries('PRIVATE_SECRET '.repeat(5000));
  expect(oversized.status).toBe('LIMIT_EXCEEDED');
  expect(oversized.groups).toEqual([]);
  const deep='{'.repeat(12)+'"secret":1'+'}'.repeat(12);
  expect(reviewLogicalBoundaries(deep).status).toBe('REVIEW_REQUIRED');
  const many=Array.from({length:501},()=>'{ "action":"allow" }').join('\n');
  expect(reviewLogicalBoundaries(many).status).toBe('LIMIT_EXCEEDED');
 });
});
