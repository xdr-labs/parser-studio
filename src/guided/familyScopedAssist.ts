/**
 * ChatGPT Assisted on a draft whose event families have their own mappings (event profiles).
 *
 * ParserRecipe v0.2 has no family routing, and the conditional draft must not lose it. So one family is worked on
 * at a time: projectFamilyDraft gives the ordinary single-family draft that reads that family exactly as the routed
 * draft does (the shared mappings plus the mappings of the family), which v0.2 can express and the existing
 * prompt, review, comparison and holdout path can check on the records of that family. mergeFamilyCandidate puts
 * a reviewed result back into that family only: the source format, the shared mappings, the enrichment and the
 * classification must be unchanged, no destination may be written twice in one event, and the other families keep
 * their mappings. Records of no family (UNRECOGNIZED_EVENT_FAMILY) form their own scope; a result for them becomes
 * a new family selected by the value of the existing discriminator.
 */
import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {lookupFieldValue} from '../fieldPaths';
import {eventFamilyValue,isCarriedFamilyMapping,validateEventProfiles,type EventProfile} from './multiEventRouting';
import type {FieldGroup} from './contract';

export const UNRECOGNIZED_SCOPE='unrecognized';
export interface FamilyScope{
  name:string;
  /** Record indexes of the sample, in order. */
  records:number[];
  /** READ: every record of the family is parsed and normalized completely. */
  state:'READ'|'PARTIAL'|'UNRECOGNIZED';
}
export type FamilyMergeResult={ok:true;draft:ParserDraft}|{ok:false;reason:
  'NO_EVENT_PROFILES'|'UNKNOWN_FAMILY'|'SOURCE_FORMAT_CHANGED'|'SHARED_MAPPING_CHANGED'|'ENRICHMENT_CHANGED'|
  'CLASSIFICATION_CHANGED'|'NO_FAMILY_MAPPING'|'DESTINATION_COLLISION'|'NO_SINGLE_DISCRIMINATOR_VALUE'|
  'INVALID_FAMILY'|'SOURCE_NOT_IN_FAMILY'|'NO_FAMILY_CHANGE'|'FAMILY_SOURCE_REMOVED'};

const EXTRACTION_KEYS=['format','pattern','csvColumns','csvDelimiter','syslogBodyFormat','mixedFormats',
  'genericStructuralProfile','genericStructuralFamilyGrammar','forwarder','omitSourceRaw'] as const;
const FAMILY_NAME=/^[a-z][a-z0-9_-]{0,31}$/u;

export function familyScopes(draft:ParserDraft,suite:SuiteResult|undefined):FamilyScope[]|null{
  const profiles=draft.eventProfiles;
  if(!profiles||!suite)return null;
  const known=new Set(profiles.variants.map(variant=>variant.name));
  const byName=new Map<string,number[]>();
  for(const [index,event] of suite.events.entries()){
    const name=event.eventFamily&&known.has(event.eventFamily)?event.eventFamily:UNRECOGNIZED_SCOPE;
    byName.set(name,[...(byName.get(name)??[]),index]);
  }
  const scopes:FamilyScope[]=[];
  for(const variant of profiles.variants){
    const records=byName.get(variant.name);
    if(!records)continue;
    const read=records.every(index=>{
      const event=suite.events[index]!;
      return event.extracted&&event.normalizedOk&&(event.parseStatus??'FULL')==='FULL';
    });
    scopes.push({name:variant.name,records,state:read?'READ':'PARTIAL'});
  }
  const rest=byName.get(UNRECOGNIZED_SCOPE);
  if(rest)scopes.push({name:UNRECOGNIZED_SCOPE,records:rest,state:'UNRECOGNIZED'});
  return scopes;
}

/** The original lines of one scope, in their order, unchanged. */
/** The original records of a family, in order, exactly as the preview read them. Record indexes are preview
 * events, not physical lines: blank lines and multi-line records make the two differ (audit F1). */
export function familySource(suite:SuiteResult,scope:FamilyScope):string{
  return scope.records.map(index=>suite.events[index]!.raw).join('\n');
}

/** The ordinary draft that reads one family as the routed draft does: shared plus family mappings. A carried
 * mapping (isCarriedFamilyMapping) reads nothing in the records of the family and is left out. */
export function projectFamilyDraft(draft:ParserDraft,name:string):ParserDraft|null{
  const profiles=draft.eventProfiles;
  if(!profiles)return null;
  const variant=profiles.variants.find(item=>item.name===name);
  if(!variant&&name!==UNRECOGNIZED_SCOPE)return null;
  const own=(variant?.mappings??[]).filter(rule=>!isCarriedFamilyMapping(rule));
  const projected:ParserDraft={...draft,mappings:[...draft.mappings,...own]};
  delete projected.eventProfiles;
  return projected;
}

const groupOf=(draft:ParserDraft,rule:MappingRule):FieldGroup=>draft.guided?.groups[rule.id]??'vendor_fields';
// The source path kind is part of what a mapping reads (re-audit A3): a literal key differs from the nested
// path of the same name. A mapping without a kind reads the nested path, so it equals the same mapping marked
// "nested" (JSONata marks every dotted selector; re-audit 2 F2).
const keyOf=(draft:ParserDraft,rule:MappingRule)=>JSON.stringify([rule.source,rule.target,rule.type,groupOf(draft,rule),rule.when??null,
  rule.sourcePathKind==='literal_root'?'literal_root':'nested']);
const outputOf=(draft:ParserDraft,rule:MappingRule)=>(groupOf(draft,rule)==='vendor_fields'?'\u0000vendor.':'')+rule.target;
const overlaps=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');

export function mergeFamilyCandidate(
  draft:ParserDraft,name:string,candidate:ParserDraft,suite:SuiteResult,
):FamilyMergeResult{
  const profiles=draft.eventProfiles;
  if(!profiles)return {ok:false,reason:'NO_EVENT_PROFILES'};
  const index=profiles.variants.findIndex(variant=>variant.name===name);
  if(index<0&&name!==UNRECOGNIZED_SCOPE)return {ok:false,reason:'UNKNOWN_FAMILY'};
  for(const key of EXTRACTION_KEYS)
    if(JSON.stringify(draft[key]??null)!==JSON.stringify(candidate[key]??null))return {ok:false,reason:'SOURCE_FORMAT_CHANGED'};
  if(JSON.stringify(draft.guided?.enrichment??[])!==JSON.stringify(candidate.guided?.enrichment??[]))
    return {ok:false,reason:'ENRICHMENT_CHANGED'};
  if(JSON.stringify(draft.guided?.classification??null)!==JSON.stringify(candidate.guided?.classification??null))
    return {ok:false,reason:'CLASSIFICATION_CHANGED'};
  const shared=new Set(draft.mappings.map(rule=>keyOf(draft,rule)));
  const offered=new Set(candidate.mappings.map(rule=>keyOf(candidate,rule)));
  if([...shared].some(key=>!offered.has(key)))return {ok:false,reason:'SHARED_MAPPING_CHANGED'};
  const own=candidate.mappings.filter(rule=>!shared.has(keyOf(candidate,rule)));
  if(!own.length)return {ok:false,reason:'NO_FAMILY_MAPPING'};
  // Each mapping of this family reads a value that some record of this family has: a result made for another
  // family, or a source path of another family, would otherwise map nothing here or mix families.
  const records=(familyScopes(draft,suite)??[]).find(scope=>scope.name===name)?.records??[];
  for(const rule of own)
    if(!records.some(at=>{
      // Read as the mapping reads it: a literal-key mapping finds only the literal key (re-audit 2 F3).
      const found=lookupFieldValue(suite.events[at]!.fields,rule.source,rule.sourcePathKind);
      return found.found&&found.value!==undefined&&found.value!==null&&typeof found.value!=='object';
    }))return {ok:false,reason:'SOURCE_NOT_IN_FAMILY'};
  // A result keeps every source the family maps: a source it leaves out would vanish from FULL events of the
  // family (re-audit 2026-11-23, Q2-5). Carried sources are kept by the merge itself.
  if(index>=0){
    const kept=new Set([...draft.mappings,...own].map(rule=>rule.source));
    if(profiles.variants[index]!.mappings.some(rule=>!isCarriedFamilyMapping(rule)&&!kept.has(rule.source)))
      return {ok:false,reason:'FAMILY_SOURCE_REMOVED'};
  }
  // A result that leaves the family as it is is reported, not applied as a change (audit F4).
  if(index>=0){
    const before=profiles.variants[index]!.mappings.filter(rule=>!isCarriedFamilyMapping(rule))
      .map(rule=>keyOf(draft,rule)).sort();
    const after=own.map(rule=>keyOf(candidate,rule)).sort();
    if(JSON.stringify(before)===JSON.stringify(after))return {ok:false,reason:'NO_FAMILY_CHANGE'};
  }
  // One destination at most once per event: the shared outputs and the outputs of this family.
  const seen=draft.mappings.map(rule=>outputOf(draft,rule));
  for(const rule of own){
    const out=outputOf(candidate,rule);
    if(seen.some(other=>overlaps(other,out)))return {ok:false,reason:'DESTINATION_COLLISION'};
    seen.push(out);
  }
  const taken=new Set([...draft.mappings,...profiles.variants.flatMap(variant=>variant.mappings)].map(rule=>rule.id));
  const groups:Record<string,FieldGroup>={...(draft.guided?.groups??{})};
  const slot=index<0?profiles.variants.length:index;
  const mappings=own.map((rule,n)=>{
    let id='family-'+String(slot)+'-ai-'+String(n);
    while(taken.has(id))id+='x';
    taken.add(id);groups[id]=groupOf(candidate,rule);
    return {...rule,id};
  });
  let variants:EventProfile[];
  if(index>=0){
    // The carried mappings stay, unless the result now maps their source itself. A result that writes the output
    // of a carried mapping would drop that source's value: it is refused (re-audit 2026-11-23, Q2-4).
    const outputs=[...draft.mappings.map(rule=>outputOf(draft,rule)),...own.map(rule=>outputOf(candidate,rule))];
    const sources=new Set(own.map(rule=>rule.source));
    const carried=profiles.variants[index]!.mappings.filter(rule=>isCarriedFamilyMapping(rule)&&!sources.has(rule.source));
    if(carried.some(rule=>outputs.some(other=>overlaps(other,outputOf(draft,rule)))))
      return {ok:false,reason:'DESTINATION_COLLISION'};
    for(const rule of profiles.variants[index]!.mappings)if(!carried.includes(rule))delete groups[rule.id];
    variants=profiles.variants.map((variant,i)=>i===index?{...variant,mappings:[...mappings,...carried]}:variant);
  }else{
    const values=new Set(suite.events.filter(event=>!event.eventFamily||
      !profiles.variants.some(variant=>variant.name===event.eventFamily))
      .map(event=>eventFamilyValue(event,profiles.discriminator)??''));
    const [value]=[...values];
    if(values.size!==1||!value||profiles.variants.some(variant=>variant.equals===value))
      return {ok:false,reason:'NO_SINGLE_DISCRIMINATOR_VALUE'};
    const familyName=FAMILY_NAME.test(value)?value:
      value.toLowerCase().replace(/[^a-z0-9_-]/gu,'_').replace(/^[^a-z]+/u,'').slice(0,32);
    if(!FAMILY_NAME.test(familyName)||profiles.variants.some(variant=>variant.name===familyName))
      return {ok:false,reason:'INVALID_FAMILY'};
    variants=[...profiles.variants,{name:familyName,equals:value,mappings}];
  }
  const eventProfiles={...profiles,variants};
  if(validateEventProfiles(eventProfiles)!==null)return {ok:false,reason:'INVALID_FAMILY'};
  return {ok:true,draft:{...draft,eventProfiles,guided:{...draft.guided!,groups}}};
}

/**
 * Manual mapping on one event type (Map Fields; owner decision of 2026-11-25: automatic, ChatGPT Assisted and manual
 * mapping are available for every parser). `edited` is the single-type draft of projectFamilyDraft after the user
 * added, changed or removed matches. A match that was shared stays shared, so its change applies to every type;
 * the other matches become the matches of this type. Carried matches and the other types are kept as they are.
 * How the source is read must be unchanged, and no destination may be written twice in one event of any type.
 */
export function applyFamilyMappingEdit(draft:ParserDraft,name:string,edited:ParserDraft):FamilyMergeResult{
  const profiles=draft.eventProfiles;
  if(!profiles)return {ok:false,reason:'NO_EVENT_PROFILES'};
  const index=profiles.variants.findIndex(variant=>variant.name===name);
  if(index<0)return {ok:false,reason:'UNKNOWN_FAMILY'};
  for(const key of EXTRACTION_KEYS)
    if(JSON.stringify(draft[key]??null)!==JSON.stringify(edited[key]??null))return {ok:false,reason:'SOURCE_FORMAT_CHANGED'};
  const sharedIds=new Set(draft.mappings.map(rule=>rule.id));
  const current=profiles.variants[index]!;
  // A carried match stays unless the type now maps its source itself.
  const ownSources=new Set(edited.mappings.filter(rule=>!sharedIds.has(rule.id)).map(rule=>rule.source));
  const carried=current.mappings.filter(rule=>isCarriedFamilyMapping(rule)&&!ownSources.has(rule.source));
  const elsewhere=new Set([...carried,...profiles.variants.flatMap((variant,at)=>at===index?[]:variant.mappings)].map(rule=>rule.id));
  const groups:Record<string,FieldGroup>={...(draft.guided?.groups??{})};
  for(const rule of [...draft.mappings,...current.mappings])if(!carried.includes(rule))delete groups[rule.id];
  const shared:MappingRule[]=[],own:MappingRule[]=[];
  for(const rule of edited.mappings){
    const group=groupOf(edited,rule);
    if(sharedIds.has(rule.id)){shared.push(rule);groups[rule.id]=group;continue;}
    // An id another type (or a carried match) uses would make two matches share one group entry.
    let id=rule.id;
    while(elsewhere.has(id)||sharedIds.has(id)||own.some(other=>other.id===id))id='family-'+String(index)+'-'+id;
    own.push(id===rule.id?rule:{...rule,id});groups[id]=group;
  }
  const variants=profiles.variants.map((variant,at)=>at===index?{...variant,mappings:[...own,...carried]}:variant);
  const eventProfiles={...profiles,variants};
  const next:ParserDraft={...draft,mappings:shared,eventProfiles,guided:{...(draft.guided??edited.guided)!,groups}};
  // One destination at most once per event: the shared outputs and the outputs of each type.
  for(const variant of variants){
    const seen:string[]=[];
    for(const rule of [...shared,...variant.mappings]){
      const out=outputOf(next,rule);
      if(seen.some(other=>overlaps(other,out)))return {ok:false,reason:'DESTINATION_COLLISION'};
      seen.push(out);
    }
  }
  if(validateEventProfiles(eventProfiles)!==null)return {ok:false,reason:'INVALID_FAMILY'};
  return {ok:true,draft:next};
}

const countText=(count:number)=>count+(count===1?' record':' records');
const stateText=(state:FamilyScope['state'])=>state==='READ'?'read completely':state==='PARTIAL'?'partly read':'not recognized';
const ruleText=(draft:ParserDraft,rule:MappingRule)=>'  - '+rule.source+' -> '+rule.target+' ('+rule.type+', '+groupOf(draft,rule)+')';

/** Prompt context for ChatGPT Assisted on one family of a routed draft: the routing field, every family with its
 * record count, state and mappings, and the families still to support. Names and counts only: the selected
 * family's original lines are the prompt source, and other families' lines are not repeated here. */
export function familyPromptContext(draft:ParserDraft,scopes:FamilyScope[],selected:string):string{
  const profiles=draft.eventProfiles;
  if(!profiles)return '';
  const remaining=scopes.filter(scope=>scope.state!=='READ');
  const lines=[
    'This parser reads several event types with separate mappings (event profiles). Improve only event type '+selected+'.',
    'The original logs in this prompt are the records of '+selected+' only. Do not change how the shared log format is read,',
    'do not change or remove the shared mappings, and do not map a Stellar Cyber field that another mapping of this parser already fills.',
    'Discriminator field: '+profiles.discriminator+' (records with an unknown value are rejected, never guessed).',
    'Event types still to support: '+(remaining.length
      ?remaining.map(scope=>scope.name+' ('+countText(scope.records.length)+')').join(', '):'none'),
    'Shared mappings for every event type:',
    ...(draft.mappings.length?draft.mappings.map(rule=>ruleText(draft,rule)):['  - none']),
  ];
  for(const scope of scopes){
    const variant=profiles.variants.find(item=>item.name===scope.name);
    lines.push(scope.name+': '+countText(scope.records.length)+', '+stateText(scope.state)+
      (scope.name===selected?' (selected)':'')+(variant?'; discriminator value '+JSON.stringify(variant.equals):''));
    // A carried mapping is named as such: it keeps a source of another event type and is kept on merge.
    if(variant)lines.push(...(variant.mappings.length?variant.mappings.map(rule=>ruleText(draft,rule)+
      (isCarriedFamilyMapping(rule)?' [kept for a source of another event type]':'')):['  - no type-specific mappings']));
  }
  return lines.join('\n');
}
