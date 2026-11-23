import {describe,expect,it} from 'vitest';
import {createDraft,type MappingRule,type ParserDraft} from '../model';
import {preview} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {buildReviewableRecipe} from './parserRecipeV2';
import {toBackendProject} from './backendAdapter';
import {familyScopes,familySource,projectFamilyDraft,mergeFamilyCandidate,familyPromptContext} from './familyScopedAssist';

// ChatGPT Assisted on a draft whose event families have their own mappings (event profiles). One family is
// projected to an ordinary single-family draft - expressible as ParserRecipe v0.2 - and a reviewed result is
// merged back into that family only. SYNTHETIC lines after the documented formats.
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const PAN2=PAN.replace('10.10.20.15','10.10.20.16');
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const CEF2=CEF.replace('10.0.0.7','10.0.0.9');
const OTHER='<14>Oct 15 00:03:22 PA-FW01 {"srcip":"10.9.9.9","action":"allow"}';
const SAMPLE=[PAN,CEF,PAN2,CEF2].join('\n');

function routed():ParserDraft{
  const built=buildAutomaticGenericStructuralDraft(SAMPLE,createDraft());
  expect(built?.draft.eventProfiles).toBeDefined();
  return built!.draft;
}
const official=(draft:ParserDraft,source:string)=>preview(source,draft).events.map(event=>{
  const out=event.normalized as Record<string,unknown>;
  return Object.fromEntries(['srcip','dstip','srcport','dstport'].filter(key=>key in out).map(key=>[key,String(out[key])]));
});
const groupOf=(draft:ParserDraft,rule:MappingRule)=>draft.guided?.groups[rule.id]??'vendor_fields';

describe('the event families of a routed draft are offered as separate scopes',()=>{
  it('lists every family with its records, in order, and the records of no family',()=>{
    const draft=routed();
    const source=[PAN,CEF,OTHER,PAN2].join('\n');
    const scopes=familyScopes(draft,preview(source,draft))!;
    expect(scopes.map(scope=>[scope.name,scope.records,scope.state])).toEqual([
      ['panos_traffic_csv',[0,3],'READ'],['structured_family_cef',[1],'READ'],['unrecognized',[2],'UNRECOGNIZED']]);
    expect(familySource(preview(source,draft),scopes[2]!)).toBe(OTHER);
    expect(familySource(preview(source,draft),scopes[0]!)).toBe([PAN,PAN2].join('\n'));
  });
  it('a draft without event profiles has no family scopes',()=>{
    const draft=buildAutomaticGenericStructuralDraft([PAN,PAN2].join('\n'),createDraft())!.draft;
    expect(familyScopes(draft,preview([PAN,PAN2].join('\n'),draft))).toBeNull();
  });
});

describe('one family as an ordinary draft',()=>{
  it('reads the family records exactly as the routed draft does and is expressible as ParserRecipe v0.2',async()=>{
    const draft=routed();
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    expect(cef.eventProfiles).toBeUndefined();
    const lines=[CEF,CEF2].join('\n');
    expect(official(cef,lines)).toEqual(official(draft,lines));
    const suite=preview(lines,cef);
    const recipe=await buildReviewableRecipe(lines,cef,suite);
    expect(recipe.ok,JSON.stringify(recipe)).toBe(true);
  });
});

describe('a reviewed family result is merged into that family only',()=>{
  const addMapping=(draft:ParserDraft,rule:MappingRule,group:'top_fields'|'ns_fields'|'vendor_fields'):ParserDraft=>({
    ...draft,mappings:[...draft.mappings,rule],guided:{...draft.guided!,groups:{...draft.guided!.groups,[rule.id]:group}}});
  it('adds the new family mapping and leaves the shared mappings and the other families untouched',()=>{
    const draft=routed();
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    const candidate=addMapping(cef,{id:'ai-1',authoring:{version:1,origin:'REVIEW_REQUIRED'},
      source:'body.cef_name',target:'event_name',type:'string'},'top_fields');
    const merged=mergeFamilyCandidate(draft,'structured_family_cef',candidate,preview(SAMPLE,draft));
    expect(merged.ok,JSON.stringify(merged)).toBe(true);
    if(!merged.ok)return;
    const pan=(d:ParserDraft)=>d.eventProfiles!.variants.find(variant=>variant.name==='panos_traffic_csv')!.mappings;
    expect(pan(merged.draft)).toEqual(pan(draft));
    expect(merged.draft.mappings).toEqual(draft.mappings);
    const out=preview(SAMPLE,merged.draft).events.map(event=>(event.normalized as Record<string,unknown>).event_name);
    expect(out).toEqual([undefined,'Login',undefined,'Login']);
    expect(official(merged.draft,SAMPLE)).toEqual(official(draft,SAMPLE));
    expect(toBackendProject(merged.draft).ok).toBe(true);
  });
  it('refuses a result that changes the source format, a shared mapping or another destination of the event',()=>{
    const draft=routed();
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    const suite=preview(SAMPLE,draft);
    expect(mergeFamilyCandidate(draft,'structured_family_cef',{...cef,format:'kv'},suite)).toMatchObject({ok:false,reason:'SOURCE_FORMAT_CHANGED'});
    const sharedRule=draft.mappings[0];
    if(sharedRule){
      const changed={...cef,mappings:cef.mappings.map(rule=>rule.id===sharedRule.id?{...rule,target:'srcip'}:rule)};
      expect(mergeFamilyCandidate(draft,'structured_family_cef',changed,suite)).toMatchObject({ok:false});
    }
    const official=cef.mappings.find(rule=>groupOf(cef,rule)!=='vendor_fields')!;
    const twice=addMapping(cef,{id:'ai-2',authoring:{version:1,origin:'REVIEW_REQUIRED'},
      source:'body.cef_name',target:official.target,type:'string'},'top_fields');
    expect(mergeFamilyCandidate(draft,'structured_family_cef',twice,suite)).toMatchObject({ok:false,reason:'DESTINATION_COLLISION'});
  });
  it('adds a family that was not in the sample, selected by its own reading mode',()=>{
    const draft=routed();
    const source=[PAN,CEF,OTHER,PAN2].join('\n');
    const suite=preview(source,draft);
    const base=projectFamilyDraft(draft,'unrecognized')!;
    const lines=familySource(suite,familyScopes(draft,suite)!.find(scope=>scope.name==='unrecognized')!);
    const fields=preview(lines,base).events[0]!.fields;
    const ip=Object.keys(fields.body as object).includes('srcip')?'body.srcip':'srcip';
    const candidate=addMapping(base,{id:'ai-3',authoring:{version:1,origin:'REVIEW_REQUIRED'},
      source:ip,target:'srcip',type:'ip'},'top_fields');
    const merged=mergeFamilyCandidate(draft,'unrecognized',candidate,suite);
    expect(merged.ok,JSON.stringify(merged)).toBe(true);
    if(!merged.ok)return;
    expect(merged.draft.eventProfiles!.variants.length).toBe(3);
    const after=preview(source,merged.draft);
    expect(after.events.map(event=>event.diagnostics.some(item=>item.code==='UNRECOGNIZED_EVENT_FAMILY'))).toEqual([false,false,false,false]);
    expect(official(merged.draft,source)[2]).toEqual({srcip:'10.9.9.9'});
    expect(official(merged.draft,[PAN,CEF].join('\n'))).toEqual(official(draft,[PAN,CEF].join('\n')));
  });
});

describe('the prompt for one event family describes the whole routed parser',()=>{
  it('names the selected family, every other family with its mappings, and the families still to support',()=>{
    const draft=routed();
    const source=[PAN,CEF,OTHER,PAN2].join('\n');
    const scopes=familyScopes(draft,preview(source,draft))!;
    const text=familyPromptContext(draft,scopes,'structured_family_cef');
    expect(text).toContain('Improve only event type structured_family_cef');
    expect(text).toContain('Discriminator field: '+draft.eventProfiles!.discriminator);
    const pan=draft.eventProfiles!.variants.find(variant=>variant.name==='panos_traffic_csv')!;
    expect(pan.mappings.length).toBeGreaterThan(0);
    for(const rule of pan.mappings)expect(text).toContain(rule.source+' -> '+rule.target);
    for(const rule of draft.mappings)expect(text).toContain(rule.source+' -> '+rule.target);
    expect(text).toMatch(/panos_traffic_csv: 2 records, read completely/);
    expect(text).toContain('Event types still to support: unrecognized (1 record)');
    // Names and counts only: other families' original lines are not repeated here.
    expect(text).not.toContain('10.10.20.15');
    expect(text).not.toContain('10.9.9.9');
  });
});

describe('a reviewed result is applied only to the event type it was made for',()=>{
  it('rejects a CEF result applied to the PAN-OS TRAFFIC event type',()=>{
    const draft=routed();
    const source=[PAN,CEF,PAN2,CEF2].join('\n');
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    const merged=mergeFamilyCandidate(draft,'panos_traffic_csv',cef,preview(source,draft));
    expect(merged).toEqual({ok:false,reason:'SOURCE_NOT_IN_FAMILY'});
  });
  it('rejects a mapping whose source exists only in another event type',()=>{
    const draft=routed();
    const source=[PAN,CEF,PAN2,CEF2].join('\n');
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    const candidate:ParserDraft={...cef,mappings:[...cef.mappings,{id:'ai-x',source:'generic.fields.app',target:'appid_name',type:'string'}],
      guided:{...cef.guided!,groups:{...cef.guided!.groups,'ai-x':'top_fields'}}};
    expect(mergeFamilyCandidate(draft,'structured_family_cef',candidate,preview(source,draft)))
      .toEqual({ok:false,reason:'SOURCE_NOT_IN_FAMILY'});
  });
});

describe('audit F1 and F3: family records and shared mappings',()=>{
  it('takes the records of a family from the preview even when the sample has blank lines',()=>{
    const draft=routed();
    const source=[PAN,'',CEF,PAN2,'',CEF2].join('\n');
    const suite=preview(source,draft);
    const scopes=familyScopes(draft,suite)!;
    expect(familySource(suite,scopes.find(scope=>scope.name==='structured_family_cef')!)).toBe([CEF,CEF2].join('\n'));
    expect(familySource(suite,scopes.find(scope=>scope.name==='panos_traffic_csv')!)).toBe([PAN,PAN2].join('\n'));
  });
  it('refuses a result that removes a mapping shared by every family',()=>{
    const base=routed();
    const draft:ParserDraft={...base,mappings:[{id:'shared-1',source:'generic.mode',target:'parser_mode',type:'string'}],
      guided:{...base.guided!,groups:{...base.guided!.groups,'shared-1':'vendor_fields'}}};
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    expect(cef.mappings.some(rule=>rule.id==='shared-1')).toBe(true);
    const removed={...cef,mappings:cef.mappings.filter(rule=>rule.id!=='shared-1')};
    expect(mergeFamilyCandidate(draft,'structured_family_cef',removed,preview(SAMPLE,draft)))
      .toEqual({ok:false,reason:'SHARED_MAPPING_CHANGED'});
  });
  it('reports an unchanged result instead of applying it (audit F4)',()=>{
    const draft=routed();
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    expect(mergeFamilyCandidate(draft,'structured_family_cef',cef,preview(SAMPLE,draft)))
      .toEqual({ok:false,reason:'NO_FAMILY_CHANGE'});
  });
  it('accepts a result that restates a shared mapping with the nested path kind it already reads (re-audit 2 F2)',()=>{
    const base=routed();
    const draft:ParserDraft={...base,mappings:[{id:'shared-1',source:'generic.mode',target:'parser_mode',type:'string'}],
      guided:{...base.guided!,groups:{...base.guided!.groups,'shared-1':'vendor_fields'}}};
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    const candidate={...cef,mappings:cef.mappings.map(rule=>rule.id==='shared-1'?{...rule,sourcePathKind:'nested' as const}:
      rule.source==='body.cef_name'?{...rule,target:'event_name'}:rule),
      guided:{...cef.guided!,groups:{...cef.guided!.groups,...Object.fromEntries(cef.mappings
        .filter(rule=>rule.source==='body.cef_name').map(rule=>[rule.id,'top_fields' as const]))}}};
    const merged=mergeFamilyCandidate(draft,'structured_family_cef',candidate,preview(SAMPLE,draft));
    expect(merged.ok,JSON.stringify(merged)).toBe(true);
  });
  it('reads a literal-key mapping as written when it checks the records of the family (re-audit 2 F3)',()=>{
    const draft=routed();
    const cef=projectFamilyDraft(draft,'structured_family_cef')!;
    // No record has a literal top-level key "body.cef_name": the literal reading finds nothing.
    const literal={...cef,mappings:cef.mappings.map(rule=>rule.source==='body.cef_name'?{...rule,sourcePathKind:'literal_root' as const}:rule)};
    expect(mergeFamilyCandidate(draft,'structured_family_cef',literal,preview(SAMPLE,draft)))
      .toEqual({ok:false,reason:'SOURCE_NOT_IN_FAMILY'});
  });
});
