/**
 * Manual mapping on one event type of a parser with event profiles (owner decision of 2026-11-25): the mapping
 * flow is the same for every parser, automatic -> ChatGPT Assisted -> by hand. Map Fields shows one event type as
 * an ordinary single-type draft (projectFamilyDraft); applyFamilyMappingEdit puts the edited draft back into that
 * type only. SYNTHETIC drafts.
 */
import {describe,expect,it} from 'vitest';
import {createDraft,type MappingRule,type ParserDraft} from '../model';
import {defaultGuidedOptions} from './contract';
import {applyFamilyMappingEdit,projectFamilyDraft} from './familyScopedAssist';

const rule=(id:string,source:string,target:string,type:MappingRule['type']='string'):MappingRule=>({id,source,target,type});
function draft():ParserDraft{
  return {...createDraft(),format:'mixed',mappings:[rule('shared-host','syslog_hostname','hostname')],
    eventProfiles:{discriminator:'parserstudio_event_family',unknown:'reject',variants:[
      {name:'cef',equals:'cef',mappings:[rule('family-0-auto-0','src','srcip','ip'),rule('family-0-auto-1','act','action'),
        rule('family-0-carried-0','body.sensor','sensor')]},
      {name:'json',equals:'json',mappings:[rule('family-1-auto-0','src_ip','srcip','ip'),rule('family-1-auto-1','sensor','sensor')]}]},
    guided:{...defaultGuidedOptions(),groups:{'shared-host':'top_fields','family-0-auto-0':'top_fields','family-0-auto-1':'top_fields',
      'family-0-carried-0':'vendor_fields','family-1-auto-0':'top_fields','family-1-auto-1':'vendor_fields'}},
  } as unknown as ParserDraft;
}
const edit=(base:ParserDraft,name:string,change:(scoped:ParserDraft)=>ParserDraft)=>applyFamilyMappingEdit(base,name,change(projectFamilyDraft(base,name)!));
const variant=(value:ParserDraft,name:string)=>value.eventProfiles!.variants.find(item=>item.name===name)!;
const withGroup=(scoped:ParserDraft,id:string,group:'top_fields'|'vendor_fields'):ParserDraft=>({...scoped,
  guided:{...scoped.guided!,groups:{...scoped.guided!.groups,[id]:group}}});

describe('manual mapping on one event type',()=>{
  it('shows the shared matches and the matches of the type, not those of another type or carried ones',()=>{
    expect(projectFamilyDraft(draft(),'json')!.mappings.map(item=>item.id)).toEqual(['shared-host','family-1-auto-0','family-1-auto-1']);
  });

  it('adds a match to that type only',()=>{
    const result=edit(draft(),'json',scoped=>withGroup({...scoped,mappings:[...scoped.mappings,rule('manual-bytes','bytes','bytes_total','integer')]},'manual-bytes','vendor_fields'));
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(variant(result.draft,'json').mappings.map(item=>item.source)).toEqual(['src_ip','sensor','bytes']);
    expect(variant(result.draft,'cef')).toEqual(variant(draft(),'cef'));
    expect(result.draft.mappings).toEqual(draft().mappings);
    expect(result.draft.guided!.groups['manual-bytes']).toBe('vendor_fields');
  });

  it('changes the destination of a match of that type',()=>{
    const result=edit(draft(),'cef',scoped=>({...scoped,mappings:scoped.mappings.map(item=>item.id==='family-0-auto-1'?{...item,target:'event_name'}:item)}));
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(variant(result.draft,'cef').mappings.find(item=>item.source==='act')!.target).toBe('event_name');
    expect(variant(result.draft,'json')).toEqual(variant(draft(),'json'));
  });

  it('removes a match of that type, keeps its carried matches and drops the group of the removed match',()=>{
    const result=edit(draft(),'cef',scoped=>({...scoped,mappings:scoped.mappings.filter(item=>item.id!=='family-0-auto-0')}));
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(variant(result.draft,'cef').mappings.map(item=>item.id)).toEqual(['family-0-auto-1','family-0-carried-0']);
    expect('family-0-auto-0' in result.draft.guided!.groups).toBe(false);
    expect(variant(result.draft,'json').mappings.map(item=>item.id)).toEqual(['family-1-auto-0','family-1-auto-1']);
  });

  it('gives an added match an id no other type uses',()=>{
    const result=edit(draft(),'cef',scoped=>withGroup({...scoped,mappings:[...scoped.mappings,rule('family-1-auto-1','dpt','dstport','integer')]},'family-1-auto-1','top_fields'));
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    const added=variant(result.draft,'cef').mappings.find(item=>item.source==='dpt')!;
    expect(added.id).not.toBe('family-1-auto-1');
    expect(result.draft.guided!.groups[added.id]).toBe('top_fields');
    expect(result.draft.guided!.groups['family-1-auto-1']).toBe('vendor_fields');
    expect(variant(result.draft,'json')).toEqual(variant(draft(),'json'));
  });

  it('refuses two matches that write the same destination in one event of the type',()=>{
    expect(edit(draft(),'cef',scoped=>withGroup({...scoped,mappings:[...scoped.mappings,rule('manual-dst','dst','srcip','ip')]},'manual-dst','top_fields')))
      .toEqual({ok:false,reason:'DESTINATION_COLLISION'});
    // The destination of a shared match is taken in every type.
    expect(edit(draft(),'json',scoped=>withGroup({...scoped,mappings:[...scoped.mappings,rule('manual-dev','device','hostname')]},'manual-dev','top_fields')))
      .toEqual({ok:false,reason:'DESTINATION_COLLISION'});
  });

  it('a change of a shared match applies to every type, and is refused when another type then writes a destination twice',()=>{
    const moved=edit(draft(),'json',scoped=>({...scoped,mappings:scoped.mappings.map(item=>item.id==='shared-host'?{...item,target:'dev_name'}:item)}));
    expect(moved.ok).toBe(true);
    if(moved.ok)expect(moved.draft.mappings[0]!.target).toBe('dev_name');
    expect(edit(draft(),'json',scoped=>({...scoped,mappings:scoped.mappings.map(item=>item.id==='shared-host'?{...item,target:'action'}:item)})))
      .toEqual({ok:false,reason:'DESTINATION_COLLISION'});
  });

  it('refuses a change of how the source is read, and an unknown type',()=>{
    expect(edit(draft(),'json',scoped=>({...scoped,format:'json'} as ParserDraft))).toEqual({ok:false,reason:'SOURCE_FORMAT_CHANGED'});
    expect(applyFamilyMappingEdit(draft(),'leef',projectFamilyDraft(draft(),'json')!)).toEqual({ok:false,reason:'UNKNOWN_FAMILY'});
  });
});
