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

  it('shares the bounded mapping budget across wide mixed-family events', () => {
    const draft = createDraft();
    const wide = Object.fromEntries(Array.from({length:80},(_,i)=>[
      'json_field_'+String(i).padStart(3,'0'),'value'
    ]));
    const proposed = suggestUnmappedFields([
      wide,
      {kv_only:'value'},
      {'cef_extension.src':'192.0.2.1'},
      {'leef.src':'198.51.100.1'},
    ], draft);
    expect(proposed).toHaveLength(50);
    expect(proposed.some(item=>item.source==='kv_only')).toBe(true);
    expect(proposed.some(item=>item.source==='cef_extension.src')).toBe(true);
    expect(proposed.some(item=>item.source==='leef.src')).toBe(true);
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
