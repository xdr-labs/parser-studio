/** Independent, fixed synthetic operator goldens. Expected values are authored
 * separately from every parser implementation and native callback. */
import {createDraft,type MappingRule} from '../src/model';
import type {GuidedEnrichmentRule} from '../src/guided/contract';
import fixtures from './operator-conformance.v1.json';

export interface OperatorGolden{
 id:string;raw:string;format?:'json'|'regex';pattern?:string;
 mappings:Array<Omit<MappingRule,'id'>>;enrichment?:GuidedEnrichmentRule[];
 expected:Record<string,unknown>;stage?:'extract'|'normalize'|'enrichment';
 rejected?:boolean;
}
export const OPERATOR_GOLDENS=fixtures.cases as unknown as OperatorGolden[];
export const OPERATOR_MATRIX_CONTRACT=fixtures.contract;

export function operatorGoldenFixture(item:OperatorGolden,family=false){
 const draft=createDraft();draft.vendor='Synthetic';draft.name='Contract matrix';
 draft.format=item.format??'json';draft.pattern=item.pattern??'(?<field>value)';
 draft.mappings=item.mappings.map((rule,index)=>({id:'m'+index,...rule}));
 draft.guided!.groups=Object.fromEntries(draft.mappings.map(rule=>[rule.id,'top_fields']));
 draft.guided!.classification={defaultIndex:'Syslog',rules:[]};
 draft.guided!.enrichment=item.enrichment??[];
 let raw=item.raw;
 const expected=structuredClone(item.expected);
 if(family){
  if(draft.format!=='json')throw new Error('Family fixture requires explicit JSON source');
  draft.eventProfiles={discriminator:'kind',unknown:'reject',variants:[
   {name:'security',equals:'security',mappings:[]},{name:'other',equals:'other',mappings:[]},
  ]};
  raw='{"kind":"security",'+raw.slice(1);
  if(item.stage!=='extract')expected.parserstudio_event_family='security';
 }
 return {draft,raw,expected};
}

export function expectedWireRecord(expected:Record<string,unknown>):Record<string,unknown>{
 const result=structuredClone(expected);
 if(typeof result.timestamp==='string')result.timestamp=Date.parse(result.timestamp);
 return result;
}
