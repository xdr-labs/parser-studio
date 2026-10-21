import {describe,it,expect} from 'vitest';
import {createDraft} from './model';
import {extractFields} from './parser';
import {analyzeLogEnvelopes} from './guided/autoParserEnvelope';

const duplicates=[
  '{"src_ip":"192.0.2.11","src_ip":"203.0.113.7","action":"deny"}',
  '{"outer":{"event":"one","event":"two"},"action":"deny"}',
  '{"\\u0061":"one","a":"two"}',
  '{"batch":[{"event":"one","event":"two"}]}',
];
const valid=[
  '{"left":{"k":"one"},"right":{"k":"two"}}',
  '{"batch":[{"k":"one"},{"k":"two"}]}',
  '{"message":"quoted \\"event\\" and braces { k: two }"}',
  '{"a":"one","ab":"two"}',
];

describe('JSON duplicate key source-to-draft integrity',()=>{
  it.each(duplicates)('refuses a duplicate JSON object member before dropping any value: %s',raw=>{
    const result=extractFields(raw,'json',createDraft());
    expect(result.fields).toEqual({});
    expect(result.errors).toContain('Duplicate JSON object key: review the source before generating a parser');
    const ledger=analyzeLogEnvelopes(raw,'single-line');
    expect(ledger.events[0]).toMatchObject({body:'json',status:'BODY_MALFORMED'});
    // Complete is physical record accounting, not semantic parse success.
    expect(ledger.complete).toBe(true);
    expect(ledger.unsupported).toBe(1);
  });

  it.each(valid)('keeps distinct JSON object member scopes valid: %s',raw=>{
    expect(extractFields(raw,'json',createDraft()).errors).toEqual([]);
    expect(analyzeLogEnvelopes(raw,'single-line').events[0]).toMatchObject({
      body:'json',status:'RECOGNIZED',
    });
  });
});
