import {describe,it,expect} from 'vitest';
import {createDraft} from './model';
import {extractFields,preview} from './parser';
import {reviewLogicalBoundaries} from './guided/logicalBoundaryReview';

const prefix='<34>1 2026-10-21T00:00:00Z gw app 1 EV01 - ';
const bsd='<134>Jan 16 15:19:05 gw app: ';
const malformed=[
  '{"src_ip":"192.0.2.10","src_ip":"198.51.100.10"}',
  '{"outer":{"username":"one","username":"two"}}',
  '{"\\u0061":"one","a":"two"}',
  '{"items":[{"action":"allow","action":"deny"}]}',
];

describe('explicit Syslog JSON body cannot lose repeated decoded source member names',()=>{
  it.each(malformed)('RFC5424 rejects loss of a duplicate JSON field: %s',body=>{
    const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat='json';
    const raw=prefix+body;
    const parsed=extractFields(raw,'syslog_rfc5424',draft);
    expect(parsed.fields).toEqual({});
    expect(parsed.errors).toContain('Duplicate JSON object key in reviewed Syslog body');
    const result=preview(raw,draft);
    expect(result.counts.extracted).toBe(0);
    expect(result.counts.failures).toBe(1);
    expect(result.events[0]?.raw).toBe(raw);
  });

  it.each(malformed)('RFC3164 tagged JSON body rejects duplicate objects: %s',body=>{
    const draft=createDraft();draft.format='syslog_rfc3164';draft.syslogBodyFormat='json';
    const result=extractFields(bsd+body,'syslog_rfc3164',draft);
    expect(result.fields).toEqual({});
    expect(result.errors).toContain('Duplicate JSON object key in reviewed Syslog body');
  });

  it('keeps same member names from independent sub-objects and Unicode fields valid',()=>{
    const body='{"left":{"name":"김민수"},"right":{"name":"山田"},"message":"{ brace } \\" escape"}';
    for(const [format,prefixText] of [
      ['syslog_rfc3164',bsd],['syslog_rfc5424',prefix],
    ] as const){
      const draft=createDraft();draft.format=format;draft.syslogBodyFormat='json';
      const parsed=extractFields(prefixText+body,format,draft);
      expect(parsed.errors).toEqual([]);
      expect(parsed.fields.body).toMatchObject({
        left:{name:'김민수'},right:{name:'山田'},
      });
    }
  });
});

describe('multiline JSON logical boundary review must never certify duplicate-key data loss',()=>{
  it.each([
    ['root','{\n "src_ip":"192.0.2.11",\n "src_ip":"198.51.100.11"\n}'],
    ['nested','{\n "actor": {\n "name":"one",\n "name":"two"\n }\n}'],
    ['escaped','{\n "\\u0061":1,\n "a":2\n}'],
  ])('marks %s duplicate-key JSON as review required, with no event-success claim',(_,raw)=>{
    const report=reviewLogicalBoundaries(raw);
    expect(report).toMatchObject({
      status:'REVIEW_REQUIRED',ambiguousCount:1,multilineEventCount:0,
      nativeVerified:false,targetVerified:false,sourceIncluded:false,
    });
    expect(report.groups[0]).toMatchObject({kind:'JSON_OBJECT',status:'AMBIGUOUS'});
    for(const value of ['198.51.100.11','one','name'])
      expect(JSON.stringify(report)).not.toContain(value);
  });
  it('accepts separate nested member scopes without changing the source review',()=>{
    const raw='{\n "left":{"name":"김민수"},\n "right":{"name":"山田"}\n}';
    const report=reviewLogicalBoundaries(raw);
    expect(report).toMatchObject({
      status:'REVIEWABLE_MULTILINE',ambiguousCount:0,multilineEventCount:1,
      sourceIncluded:false,
    });
  });
});
