import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { suggestUnmappedFields } from './fieldMappingSuggestions';

describe('privacy-safe, conservative all-field suggestions', () => {
  it('returns valid unmapped source names across events, without capturing any values', () => {
    const draft = createDraft();
    draft.format = 'json';
    const proposed = suggestUnmappedFields([
      {action:'allow',src_ip:'198.51.100.10',device:'EXAMPLE'},
      {action:'deny',dst_port:443,'user.name':'redacted',device:'EXAMPLE'},
    ], draft);
    expect(proposed).toEqual([
      {source:'device',target:'custom.device',type:'string',group:'vendor_fields'},
      {source:'user.name',target:'custom.user_name',type:'string',group:'vendor_fields'},
    ]);
    expect(JSON.stringify(proposed)).not.toContain('198.51.100.10');
  });

  it('rejects invalid source paths, prototype segments, collisions and duplicates', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings.push({id:'manual',source:'legacy',target:'custom.account_id',type:'string'});
    const proposed = suggestUnmappedFields([
      {'__proto__.x':'bad','constructor.name':'bad','1bad':'bad','account.id':'bad','account_id':'bad','host':'synthetic'},
    ],draft);
    expect(proposed).toEqual([{source:'host',target:'custom.host',type:'string',group:'vendor_fields'}]);
  });

  it('keeps classification operands in routable top fields', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings = draft.mappings.filter(mapping=>mapping.source!=='action');
    const suggested = suggestUnmappedFields([{action:'deny'}],draft);
    expect(suggested).toEqual([
      {source:'action',target:'custom.action',type:'string',group:'top_fields'},
    ]);
  });
});
