import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { preview } from '../parser';
import { suggestMappingType, suggestNativeJsonType } from './typeSuggestions';

function sample(events: Array<Record<string, unknown>>, source: string) {
  const draft = createDraft();
  draft.format = 'json';
  const rule = { id:'suggested', source, target:'custom.suggested', type:'string' as const };
  draft.mappings.push(rule);
  return { rule, suite: preview(events.map(item => JSON.stringify(item)).join('\n'), draft) };
}

describe('conservative privacy-safe typed suggestions; user approval required', () => {
  it.each([
    ['src_addr', ['198.51.100.10','203.0.113.11'], 'ip'],
    ['dst_port', [443,22], 'port'],
    ['enabled', ['true','false'], 'boolean'],
    ['timestamp', ['2026-10-12T00:00:00Z','2026-10-12T00:00:01Z'], 'timestamp'],
    ['attempt_count', [2,3], 'integer'],
  ] as const)('suggests %s as %s without any example contents', (field, values, expected) => {
    const {rule,suite} = sample(values.map((value) => ({[field]:value})),field);
    const result = suggestMappingType(suite,rule);
    expect(result).toEqual({type: expected, evidence: 2, total: 2});
    expect(Object.keys(result ?? {}).sort()).toEqual(['evidence', 'total', 'type']);
    if (String(values[0]).length > 5) {
      expect(JSON.stringify(result)).not.toContain(String(values[0]));
    }
  });

  it('does not coerce ambiguous IDs, booleans represented as 1/0, or mixed numeric/non-numeric', () => {
    const cases: Array<[string, unknown[]]> = [
      ['user_id', ['0012','0043']],
      ['enabled', ['0','1']],
      ['dst_port', [443, 'notaport']],
      ['timestamp', ['2026-10-12','tomorrow']],
    ];
    for (const [field,values] of cases) {
      const {rule,suite}=sample(values.map((value)=>({[field]:value})),field);
      expect(suggestMappingType(suite,rule), field).toBeNull();
    }
  });

  it('needs two relevant samples and never promotes missing fields as evidence', () => {
    const {rule,suite}=sample([{src_ip:'198.51.100.10'}, {other:'ignored'}], 'src_ip');
    expect(suggestMappingType(suite,rule)).toBeNull();
    expect(suggestMappingType(undefined,rule)).toBeNull();
  });
});

describe('native JSON typing: only what the JSON itself declares', () => {
  it.each([
    ['gid', [1, 2], 'integer'],
    ['rev', [-3, 0, 12], 'integer'],
    ['flag', [true, false], 'boolean'],
  ] as const)('suggests %s as %s from JSON numbers/booleans without values', (field, values, expected) => {
    const { rule, suite } = sample(values.map(value => ({ [field]: value })), field);
    const result = suggestNativeJsonType(suite, rule);
    expect(result).toEqual({ type: expected, evidence: values.length, total: values.length });
    expect(Object.keys(result ?? {}).sort()).toEqual(['evidence', 'total', 'type']);
  });

  it('counts only the events that carry the field', () => {
    const { rule, suite } = sample([{ gid: 1 }, { other: 'x' }, { gid: 2 }], 'gid');
    expect(suggestNativeJsonType(suite, rule)).toEqual({ type: 'integer', evidence: 2, total: 3 });
  });

  it('never promotes text, fractions, mixed kinds, unsafe integers or one observation', () => {
    const cases: Array<[string, unknown[]]> = [
      ['user_id', ['0012', '0043']],
      ['count_text', ['12', '13']],
      ['enabled', ['true', 'false']],
      ['ratio', [1, 1.5]],
      ['mixed', [1, 'x']],
      ['flagnum', [1, true]],
      ['big', [9007199254740993, 9007199254740993]],
      ['single', [5]],
    ];
    for (const [field, values] of cases) {
      const { rule, suite } = sample(values.map(value => ({ [field]: value })), field);
      expect(suggestNativeJsonType(suite, rule), field).toBeNull();
    }
    expect(suggestNativeJsonType(undefined, { id: 'x', source: 'a', target: 'a', type: 'string' })).toBeNull();
  });
});
