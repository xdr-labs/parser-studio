import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildSampleUnionSchema} from './sampleUnionSchema';
import fixtures from '../../fixtures/multilingual-security-logs.json';
import namedFields from '../../fixtures/multilingual-source-fieldnames.json';

describe('Multilingual UTF-8 source logs are data, not UI translations',()=>{
  it('preserves original bytes and non-English values when parsing JSON logs',()=>{
    const draft={...createDraft(),format:'json' as const};
    for(const item of fixtures){
      const suite=preview(item.raw,draft);
      expect(suite.events).toHaveLength(1);
      const event=suite.events[0]!;
      expect(event.extracted).toBe(true);
      expect(event.raw).toBe(item.raw);
      expect(new TextEncoder().encode(event.raw))
        .toEqual(new TextEncoder().encode(item.raw));
      expect(event.fields).toMatchObject({
        event_type:item.event_type,message:item.message,
        user:item.user,location:item.location,action:'deny',
      });
      expect(item.raw.length).toBeLessThan(new TextEncoder().encode(item.raw).byteLength);
    }
  });
  it('does not erase original Unicode field names when they are not mapped',()=>{
    const draft={...createDraft(),format:'json' as const};
    const suite=preview(namedFields.raw,draft);
    const event=suite.events[0]!;
    expect(event.extracted).toBe(true);
    expect(event.raw).toBe(namedFields.raw);
    expect(event.fields).toMatchObject(namedFields.fields);
    // Field names remain source evidence even when an output mapping
    // requires separate review. They are not translated to English.
    expect(new TextEncoder().encode(event.raw))
      .toEqual(new TextEncoder().encode(namedFields.raw));
  });
  it('retains event families and non-English source values in comparison',()=>{
    const sample=fixtures.map(item=>item.raw).join('\n');
    const draft={...createDraft(),format:'json' as const};
    const suite=preview(sample,draft);
    expect(suite.counts.total).toBe(3);
    expect(suite.events.map(event=>event.fields.message))
      .toEqual(fixtures.map(item=>item.message));
    const review=buildSampleUnionSchema(suite);
    expect(review.groups.map(group=>group.eventType))
      .toEqual(['threat','user','asset']);
    expect(review.meaning).toBe('STRUCTURAL_SAMPLE_COVERAGE_ONLY');
  });
});
