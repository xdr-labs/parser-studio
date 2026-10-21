import type {ParserDraft,MappingRule,SuiteResult} from '../model';
import {inspectEventProfile} from './multiEventRouting';
import {suggestNormalizationCandidatesFromSuite,type NormalizationCandidate} from './normalizationCandidates';
import {findStellarMetadataField} from './stellarMetadataCatalog';

export type ScopedFamilyStellar7Candidate=Pick<NormalizationCandidate,
  'source'|'target'|'type'|'group'|'confidence'|'explanation'|
  'catalogVerified'|'catalogRelease'|'observed'|'compatibleObserved'|'total'|'safeForBulk'> & {
    family:string;
  };

function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
}
function defaultTarget(source:string):string{
  return 'custom.'+source.replace(/[^A-Za-z0-9_]/g,'_');
}
function editableMapping(draft:ParserDraft,variantName:string,source:string):MappingRule|undefined{
  const variant=draft.eventProfiles?.variants.find(item=>item.name===variantName);
  const mapping=variant?.mappings.find(item=>item.source===source);
  if(!mapping||!mapping.id.startsWith('family-')||
    ![defaultTarget(source),source,source.replace(/\./g,'_')].includes(mapping.target))
    return undefined;
  if((draft.guided?.groups[mapping.id]??'vendor_fields')!=='vendor_fields')
    return undefined;
  return mapping;
}

/** Suggest independently per explicitly declared event type; never apply or
 * infer event-family routing from vendor names, file names or sample values.
 * Only authored source-key identities and aggregate counts are returned.
 */
export function proposeStellar7FamilyMappings(
  suite:SuiteResult|undefined,draft:ParserDraft,
):ScopedFamilyStellar7Candidate[]{
  if(!suite?.events.length||!draft.eventProfiles)return [];
  const config=draft.eventProfiles;
  if(suite.events.some(event=>!event.extracted||
    !inspectEventProfile(event.fields,config).profile))return [];
  const result:ScopedFamilyStellar7Candidate[]=[];
  for(const variant of config.variants){
    const events=suite.events.filter(event=>
      inspectEventProfile(event.fields,config).profile?.name===variant.name);
    if(!events.length)continue;
    const subset={...suite,events};
    const proposals=suggestNormalizationCandidatesFromSuite(subset,[],{});
    for(const candidate of proposals){
      if(!editableMapping(draft,variant.name,candidate.source))continue;
      const catalog=findStellarMetadataField(candidate.target);
      if(!catalog?.mappable||catalog.group!==candidate.group||
        catalog.mappingType!==candidate.type)continue;
      const conflictingShared=draft.mappings.some(mapping=>{
        const group=draft.guided?.groups[mapping.id]??'vendor_fields';
        return group!=='vendor_fields'&&overlaps(mapping.target,candidate.target);
      });
      const conflictingInFamily=variant.mappings.some(mapping=>{
        if(mapping.source===candidate.source)return false;
        const group=draft.guided?.groups[mapping.id]??'vendor_fields';
        return group!=='vendor_fields'&&overlaps(mapping.target,candidate.target);
      });
      const collision=conflictingShared||conflictingInFamily;
      result.push({
        family:variant.name,source:candidate.source,
        target:candidate.target,type:candidate.type,group:candidate.group,
        confidence:collision?'REVIEW':candidate.confidence,
        safeForBulk:!collision&&candidate.safeForBulk,
        explanation:collision
          ?'This Stellar destination is already used by a shared or event-type mapping. Review the conflict.'
          :candidate.explanation,
        catalogVerified:true,catalogRelease:'7.0.xs',
        observed:candidate.observed,compatibleObserved:candidate.compatibleObserved,
        total:candidate.total,
      });
    }
  }
  return result;
}
export type ScopedApplyResult=
  |{ok:true;draft:ParserDraft}
  |{ok:false;reason:string};
/** Explicit opt-in only. Never mutate an existing draft, source log or
 * previously reviewed custom/official mapping. The whole DRAFT remains local.
 */
export function applyStellar7FamilyMapping(
  draft:ParserDraft,suggestion:ScopedFamilyStellar7Candidate,suite:SuiteResult|undefined,
):ScopedApplyResult{
  // Re-check current source evidence before changing a draft. A stale or
  // externally altered recommendation never authorizes an official mapping.
  const current=proposeStellar7FamilyMappings(suite,draft).find(item=>
    item.family===suggestion.family&&item.source===suggestion.source);
  if(!current||current.target!==suggestion.target||current.type!==suggestion.type||
    current.group!==suggestion.group||current.confidence!==suggestion.confidence||
    current.safeForBulk!==suggestion.safeForBulk||
    current.observed!==suggestion.observed||current.total!==suggestion.total||
    current.compatibleObserved!==suggestion.compatibleObserved)
    return {ok:false,reason:'Re-check the current source and field evidence before applying this mapping.'};
  if(suggestion.confidence!=='HIGH'||!suggestion.safeForBulk||
    suggestion.catalogRelease!=='7.0.xs'||!suggestion.catalogVerified)
    return {ok:false,reason:'This candidate requires independent manual review.'};
  const catalog=findStellarMetadataField(suggestion.target);
  if(!catalog?.mappable||catalog.mappingType!==suggestion.type||
    catalog.group!==suggestion.group)
    return {ok:false,reason:'The destination is not an eligible typed 7.0 field.'};
  const mapping=editableMapping(draft,suggestion.family,suggestion.source);
  const variant=draft.eventProfiles?.variants.find(item=>item.name===suggestion.family);
  if(!mapping||!variant)
    return {ok:false,reason:'An existing reviewed mapping cannot be replaced automatically.'};
  for(const rule of [...draft.mappings,...variant.mappings]){
    if(rule.id===mapping.id)continue;
    if((draft.guided?.groups[rule.id]??'vendor_fields')!=='vendor_fields'&&
      overlaps(rule.target,suggestion.target))
      return {ok:false,reason:'The destination overlaps a reviewed official mapping.'};
  }
  const updated=structuredClone(draft);
  const ownVariant=updated.eventProfiles!.variants.find(item=>item.name===variant.name)!;
  const index=ownVariant.mappings.findIndex(item=>item.id===mapping.id);
  ownVariant.mappings[index]={...mapping,target:suggestion.target,type:suggestion.type};
  if(!updated.guided)
    return {ok:false,reason:'The local field-group contract is unavailable.'};
  updated.guided.groups={...updated.guided.groups,[mapping.id]:suggestion.group};
  return {ok:true,draft:updated};
}
