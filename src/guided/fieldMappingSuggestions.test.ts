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
      {source:'device',target:'device',type:'string',group:'vendor_fields'},
      {source:'user.name',target:'user_name',type:'string',group:'vendor_fields'},
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
    expect(proposed).toEqual([
      {source:'account.id',target:'account_id',type:'string',group:'vendor_fields'},
      {source:'host',target:'host',type:'string',group:'vendor_fields'},
    ]);
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
    expect(proposed).toHaveLength(83);
    expect(proposed.some(item=>item.source==='kv_only')).toBe(true);
    expect(proposed.some(item=>item.source==='cef_extension.src')).toBe(true);
    expect(proposed.some(item=>item.source==='leef.src')).toBe(true);
  });

  it('caps wide source field proposals at 100 while retaining mixed-family coverage', () => {
    const wide=Object.fromEntries(Array.from({length:150},(_,i)=>[
      'field_'+String(i).padStart(3,'0'),'value'
    ]));
    const proposed=suggestUnmappedFields([
      wide,{fortigate_only:'value'},{juniper_only:'value'},
    ],createDraft());
    expect(proposed).toHaveLength(100);
    expect(proposed.some(x=>x.source==='fortigate_only')).toBe(true);
    expect(proposed.some(x=>x.source==='juniper_only')).toBe(true);
  });

  it('keeps classification operands in routable top fields only when the destination is a real Stellar field', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings = draft.mappings.filter(mapping=>mapping.source!=='action');
    const suggested = suggestUnmappedFields([{action:'deny'}],draft);
    expect(suggested).toEqual([
      {source:'action',target:'action',type:'string',group:'top_fields'},
    ]);

    draft.guided={...draft.guided!,classification:{
      defaultIndex:'Syslog',rules:[{id:'custom',sourceField:'vendor_flag',equals:'deny',index:'Threat'}],
    }};
    expect(suggestUnmappedFields([{vendor_flag:'deny'}],draft)).toEqual([
      {source:'vendor_flag',target:'vendor_flag',type:'string',group:'vendor_fields'},
    ]);
  });
});
