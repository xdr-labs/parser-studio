import type {ParserDraft,MappingRule,SuiteResult} from '../model';
import {defaultGuidedOptions} from './contract';
import {suggestEventProfiles,validateEventProfiles} from './multiEventRouting';

export type ReviewedFamilyPlan=
 | {ok:false;reason:string}
 | {ok:true;candidate:ParserDraft;commonCount:number;
    types:Array<{name:string;sourceValue:string;fieldCount:number}>;
    removedCommonCount:number;removedClassifiers:number};

/**
 * All events must already be structurally extracted. A user explicitly
 * chooses the discriminator and approves the resulting routing plan.
 * This function never mutates the original draft or generates source code.
 */
export function planReviewedEventFamilyDraft(
  suite:SuiteResult|undefined,draft:ParserDraft,discriminator:string,
):ReviewedFamilyPlan{
  if(draft.format==='auto'||draft.format==='generic_structural'||
     draft.format==='java_stacktrace'||draft.format==='regex')
    return {ok:false,reason:'Review and select a supported explicit source format first.'};
  const proposal=suggestEventProfiles(suite,draft,discriminator.trim());
  if(!proposal.ok)return proposal;
  if(validateEventProfiles(proposal.config))
    return {ok:false,reason:'The proposed event types require manual review before routing.'};
  const opts=draft.guided??defaultGuidedOptions();
  const names=new Set(proposal.common.map(rule=>rule.source));
  const sharedMappings=[...proposal.common];
  // The discriminator should be retained even when it was not already
  // explicitly mapped. Never guess a Stellar normalized field for it.
  if(!names.has(discriminator)){
    const mapping:MappingRule={
      id:'family-shared-discriminator',source:discriminator,
      target:'custom.event_type',type:'string',
    };
    sharedMappings.push(mapping);names.add(discriminator);
  }
  const groups={...opts.groups};
  groups['family-shared-discriminator']='vendor_fields';
  for(const variant of proposal.config.variants){
    for(const mapping of variant.mappings){
      const original=draft.mappings.find(old=>old.source===mapping.source);
      groups[mapping.id]=original?opts.groups[original.id]??'vendor_fields':'vendor_fields';
    }
  }
  const classifiers=opts.classification.rules.filter(rule=>names.has(rule.sourceField));
  const removedClassifiers=opts.classification.rules.length-classifiers.length;
  const candidate:ParserDraft={
    ...draft,
    mappings:sharedMappings,
    eventProfiles:proposal.config,
    guided:{
      ...opts,groups,
      classification:{...opts.classification,rules:classifiers},
    },
  };
  return {
    ok:true,candidate,commonCount:sharedMappings.length,
    removedCommonCount:draft.mappings.length-proposal.common.length,
    removedClassifiers,
    types:proposal.config.variants.map(group=>({
      name:group.name,sourceValue:group.equals,fieldCount:group.mappings.length,
    })),
  };
}
