import {describe,expect,it} from 'vitest';
import {inspectGeneralSyslogEnvelope} from './generalSyslogEnvelopeSpans';
import {inspectPublisherQualifiedBareTag} from './publisherQualifiedBareTag';

const raw='<181>Mar 2 09:09:13 relay-x CATEGORY_A 0000075134 1 0 2022-03-02T09:09:13Z log=ok';
const qualified={sourceFraming:'PUBLISHER_ASSERTED_RFC3164_BARE_APP_TAG'} as const;

describe('independently publisher-qualified bare RFC3164 tag (isolated observer)',()=>{
  it('preserves the qualified base header and splits only the APP boundary',()=>{
    const previous=inspectGeneralSyslogEnvelope(raw);
    expect(previous.disposition).toBe('REVIEW_ONLY');
    expect(previous.fields.some(f=>f.name==='appname')).toBe(false);
    const result=inspectPublisherQualifiedBareTag(raw,qualified);
    expect(result.disposition).toBe('REVIEW_ONLY');
    expect(result.fields.find(f=>f.name==='appname')?.value).toBe('CATEGORY_A');
    expect(result.fields.find(f=>f.name==='hostname')?.value).toBe('relay-x');
    expect(result.fields.find(f=>f.name==='message')?.value)
      .toBe('0000075134 1 0 2022-03-02T09:09:13Z log=ok');
    expect(result.originalRaw).toBe(raw);
    expect(result.sourceBytes).toBe(new TextEncoder().encode(raw).length);
    expect(result.autoPromoted).toBe(false);
    expect(result.nativeParser).toBe('NOT_VERIFIED');
    expect(result.manufacturerSemantics).toBe('NOT_CERTIFIED');
  });
  it('abstains from any new source claims without an independent profile',()=>{
    const result=inspectPublisherQualifiedBareTag(raw);
    expect(result.disposition).toBe('RAW_ONLY');
    expect(result.fields).toEqual([]);
  });
  it('verifies UTF-8 exact positions while leaving escaped/empty semantics unknown',()=>{
    const value=raw.replace('log=ok','raw="é\\\\x" missing=""');
    const result=inspectPublisherQualifiedBareTag(value,qualified);
    expect(result.disposition).toBe('REVIEW_ONLY');
    const bytes=new TextEncoder().encode(value);
    for(const field of result.fields){
      expect(new TextDecoder('utf8',{fatal:true})
        .decode(bytes.slice(field.startByte,field.endByte))).toBe(field.value);
    }
    expect(result.fields.find(f=>f.name==='message')!.value).toContain('missing=""');
    expect(result.manufacturerSemantics).toBe('NOT_CERTIFIED');
  });
  it('rejects colon-tag grammar as an incompatible bare-tag profile',()=>{
    const result=inspectPublisherQualifiedBareTag(
      '<181>Mar 2 09:09:13 relay-x app[123]: native=ok',qualified);
    expect(result.disposition).toBe('ABSTAIN_UNSAFE');
    expect(result.fields).toEqual([]);
  });
  it('rejects multi-line, truncation, and invalid clocks without partial claims',()=>{
    for(const bad of [
      raw+'\n<13>Mar 2 09:10:14 another: test',
      raw.replace('09:09:13','29:09:13'),
      raw.slice(0,raw.indexOf('CATEGORY_A')+'CATEGORY_A'.length),
      raw+'X'.repeat(9000),
      raw.replace('CATEGORY_A','CEF'),
    ]){
      const result=inspectPublisherQualifiedBareTag(bad,qualified);
      expect(result.disposition).not.toBe('REVIEW_ONLY');
      expect(result.fields).toEqual([]);
    }
  });
  it('does not reinterpret RFC5424 structured data as a bare RFC3164 tag',()=>{
    const line='<34>1 2003-10-11T22:14:15.003Z host app - ID47 [x@1 v="a\\]b"] payload';
    const result=inspectPublisherQualifiedBareTag(line,qualified);
    expect(result.disposition).toBe('ABSTAIN_UNSAFE');
    expect(result.fields).toEqual([]);
  });
  it('does not exceed fixed branch/depth bounds',()=>{
    const result=inspectPublisherQualifiedBareTag(raw,qualified);
    expect(result.branchAttempts).toBeLessThanOrEqual(3);
    expect(result.maxDepth).toBe(1);
  });
});
