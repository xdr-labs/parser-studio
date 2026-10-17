import {describe,expect,it} from 'vitest';
import {inspectSourceCompleteness} from './standardSourceCompletenessGate';
import {extractFields} from '../parser';
import type {ParserDraft} from '../model';

const reviewCases=[
  ['json','{"who":"alice","who":"bob"}','DUPLICATE_MEMBER_SILENT_OVERWRITE'],
  ['json','{"score":1e999}','NONFINITE_NUMBER_OR_LOSS_OF_PRECISION'],
  ['json','{"value":"\\uD800"}','UNPAIRED_UNICODE_SURROGATE'],
  ['kv','src=192.0.2.1 dst=198.51.100.1 trailing-garbage','UNCONSUMED_TRAILING_RAW'],
  ['kv','src=192.0.2.1 msg="hello\\qworld"','UNKNOWN_PRODUCER_ESCAPE'],
] as const;

describe('STD-0 source completeness gate: baseline false-complete counterexamples',()=>{
  it.each(reviewCases)('does not certify %s malformed/uncertain source: %s',
    (family,raw,expectedIssue)=>{
      // This is an isolated PoC gate, not a change to product code.
      const browser=extractFields(raw,family,{} as ParserDraft);
      if(family==='json')expect(browser.errors.length).toBeGreaterThan(0);
      else expect(browser.errors).toEqual([]); // KV remains a measured unresolved gap
      const result=inspectSourceCompleteness(raw,family);
      expect(result.disposition).toBe('REVIEW_ONLY_UNCERTAIN');
      expect(result.issues).toContain(expectedIssue);
      expect(result.completeSourceClaim).toBe(false);
      expect(result.namedRawFields).toEqual([]);
      expect(result.raw).toBe(raw);
      expect(result.autoPromoted).toBe(false);
      expect(result.nativeStellar).toBe('NOT_VERIFIED');
    });
  it('recognizes valid JSON while refusing to treat lexical parse as complete native success',()=>{
    const raw='{"ts":"2026-10-18T01:02:03Z","value":{"tags":["a","b"]},"numbers":[0,1,-2,3.5]}';
    const result=inspectSourceCompleteness(raw,'json');
    expect(result.disposition).toBe('REVIEW_ONLY_LEXICAL');
    expect(result.issues).toEqual([]);
    expect(result.completeSourceClaim).toBe(false);
    expect(result.maxDepth).toBeLessThanOrEqual(32);
  });
  it('treats escaped-equivalent JSON names as duplicate, including nested scopes',()=>{
    const raw='{"outer":{"user":"alice","\\u0075ser":"bob"},"other":{"user":"eve"}}';
    const result=inspectSourceCompleteness(raw,'json');
    expect(result.issues).toContain('DUPLICATE_MEMBER_SILENT_OVERWRITE');
    expect(result.disposition).toBe('REVIEW_ONLY_UNCERTAIN');
  });
  it('does not mistake separate object-scoped equal names for duplicates',()=>{
    const value='{"a":{"who":"alice"},"b":{"who":"bob"}}';
    const result=inspectSourceCompleteness(value,'json');
    expect(result.disposition).toBe('REVIEW_ONLY_LEXICAL');
    expect(result.issues).toEqual([]);
  });
  it('accepts valid escaped JSON surrogate pairs and refuses isolated ones',()=>{
    expect(inspectSourceCompleteness('{"emoji":"\\uD83D\\uDE00"}','json').issues).toEqual([]);
    expect(inspectSourceCompleteness('{"emoji":"\\uD83D"}','json').issues)
      .toContain('UNPAIRED_UNICODE_SURROGATE');
  });
  it('reports integer precision risk without coercion into a certified source value',()=>{
    const out=inspectSourceCompleteness('{"counter":9007199254740993}','json');
    expect(out.issues).toContain('NONFINITE_NUMBER_OR_LOSS_OF_PRECISION');
    expect(out.sourceFieldValuesDecoded).toBe(false);
  });
  it('keeps exact source name/value UTF-8 intervals on fully consumed KV syntax',()=>{
    const raw='username=alïce action="blocked access" src=192.0.2.1';
    const out=inspectSourceCompleteness(raw,'kv');
    expect(out.disposition).toBe('REVIEW_ONLY_LEXICAL');
    expect(out.namedRawFields).toHaveLength(3);
    const bytes=Buffer.from(raw,'utf8');
    for(const field of out.namedRawFields){
      expect(bytes.subarray(field.nameStartByte,field.nameEndByte).toString('utf8'))
        .toBe(field.name);
      expect(bytes.subarray(field.valueStartByte,field.valueEndByte).toString('utf8'))
        .toBe(field.rawLexeme);
    }
    expect(out.completeSourceClaim).toBe(false);
  });
  it('keeps unquoted empty, duplicate names, truncated quoted and junk in review',()=>{
    const tests=[
      ['a=1 b=','EMPTY_ASSIGNMENT_UNQUALIFIED'],
      ['a=1 a=2','DUPLICATE_SOURCE_KEY'],
      ['a="unterminated','INVALID_SOURCE_LEXICAL_GRAMMAR'],
      ['a=1 b=2 junk','UNCONSUMED_TRAILING_RAW'],
      ['a=1b"bad"','INVALID_SOURCE_LEXICAL_GRAMMAR'],
    ] as const;
    for(const [raw,issue] of tests){
      const res=inspectSourceCompleteness(raw,'kv');
      expect(res.issues).toContain(issue);
      expect(res.namedRawFields).toEqual([]);
      expect(res.completeSourceClaim).toBe(false);
    }
  });
  it('fails closed for malformed JSON and bounded resources',()=>{
    for(const raw of ['{"a":1,}', '{"bad":"\\q"}', '{"x":1}extra', 'null{}']){
      const res=inspectSourceCompleteness(raw,'json');
      expect(res.disposition).toBe('ABSTAIN_UNSAFE');
      expect(res.issues).toContain('INVALID_SOURCE_LEXICAL_GRAMMAR');
    }
    const res=inspectSourceCompleteness('{"x":"'+('a'.repeat(66000))+'"}','json');
    expect(res.disposition).toBe('ABSTAIN_UNSAFE');
    expect(res.issues).toContain('RESOURCE_BOUNDS');
  });
});
