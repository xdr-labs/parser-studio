import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {READING_FAMILY_DISCRIMINATOR} from '../../backend/src/canonical-operator-contract';

export {READING_FAMILY_DISCRIMINATOR};

export type EventProfile= {name:string;equals:string;mappings:MappingRule[]};
export type EventProfileConfig={
 discriminator:string;unknown:'reject';variants:EventProfile[];
};
const SAFE=/^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
const FORBIDDEN=new Set(['__proto__','constructor','prototype']);
const safe=(name:string)=>name.length>0&&name.length<=128&&SAFE.test(name)&&
  name.split('.').every(part=>!FORBIDDEN.has(part));
/** The value an event has for the discriminator of a routed draft: a field of the event, or the family the
 * mixed router read it with (@reading_family, never a field). */
export function eventFamilyValue(event:{fields:Record<string,unknown>;readingFamily?:string},
  discriminator:string):string|undefined{
 if(discriminator===READING_FAMILY_DISCRIMINATOR)return event.readingFamily||undefined;
 const selected=lookupFieldValue(event.fields,discriminator);
 return selected.found&&typeof selected.value==='string'?selected.value:undefined;
}
export function inspectEventProfile(fields:Record<string,unknown>,config?:EventProfileConfig,readingFamily?:string):
 {name:string;profile:EventProfile}|{name:'UNRECOGNIZED';profile:null}{
 if(!config)return {name:'UNRECOGNIZED',profile:null};
 const value=eventFamilyValue({fields,readingFamily},config.discriminator);
 if(value===undefined)return {name:'UNRECOGNIZED',profile:null};
 const matched=config.variants.filter(p=>p.equals===value);
 if(matched.length!==1)return {name:'UNRECOGNIZED',profile:null};
 return {name:matched[0]!.name,profile:matched[0]!};
}
export function suggestEventProfiles(
 suite:SuiteResult|undefined,draft:ParserDraft,discriminator:string,
):{ok:true;config:EventProfileConfig;common:MappingRule[]}|{ok:false;reason:string}{
 if(!suite||!suite.events.length||!safe(discriminator))
   return {ok:false,reason:'Choose a safe event type field from the extracted logs.'};
 const groups=new Map<string,Set<string>>();
 for(const event of suite.events){
   if(!event.extracted)return {ok:false,reason:'Review unparsed logs first.'};
   const selected=lookupFieldValue(event.fields,discriminator);
   if(!selected.found||typeof selected.value!=='string'||!selected.value.trim()||
     selected.value.length>128||/[\x00-\x1f\x7f]/.test(selected.value))
     return {ok:false,reason:'Some events do not have a usable explicit event type.'};
   // Read one sentinel beyond the bounded field budget. A plain capped list
   // could otherwise hide additional source fields and falsely appear complete.
   const leaves=listSafeLeafPaths(event.fields,101);
   if(leaves.length>100)return {ok:false,reason:
     'A source event has over 100 safe fields. Review a smaller schema; no fields were silently dropped.'};
   const paths=groups.get(selected.value)??new Set<string>();
   for(const path of leaves)if(safe(path))paths.add(path);
   groups.set(selected.value,paths);
 }
 if(groups.size<2||groups.size>16)
   return {ok:false,reason:'Use 2–16 distinct event types with explicit source values.'};
 const names=new Set<string>();
 const values=[...groups.keys()];
 const allPaths=[...new Set([...groups.values()].flatMap(g=>[...g]))];
 const shared=new Set(allPaths.filter(path=>values.every(value=>groups.get(value)?.has(path))));
 const common=draft.mappings.filter(mapping=>shared.has(mapping.source));
 const variants:EventProfile[]=[];
 for(const [index,value] of values.entries()){
   const name=value.toLowerCase().replace(/[^a-z0-9_-]/g,'_').replace(/^[^a-z]+/,'');
   if(!name||name.length>32||names.has(name))
     return {ok:false,reason:'Event type names must have distinct safe identifiers.'};
   names.add(name);
   const fields=[...groups.get(value)!].filter(path=>!shared.has(path));
   if(fields.length>100)return {ok:false,reason:
     'An event type has over 100 distinct fields. Review a smaller schema; no fields were silently dropped.'};
   const mappings:MappingRule[]=fields.map((source,n)=>{
     const existing=draft.mappings.find(rule=>rule.source===source);
     return {id:'family-'+index+'-'+n,source,
       authoring:existing?.authoring??{version:1,origin:'AUTO'},
       target:existing?.target??'custom.'+source.replace(/[^A-Za-z0-9_]/g,'_'),
       type:existing?.type??'string'};
   });
   variants.push({name,equals:value,mappings});
 }
 return {ok:true,config:{discriminator,unknown:'reject',variants},common};
}
/**
 * A carried family mapping keeps, in a family-routed draft, a source that only another family of the sample
 * showed: as a vendor field, so that an event of this family that carries it keeps its value (a mixed parser
 * emits mapped sources only; independent audit 2026-11-23, F1). It reads nothing in the sample records of its
 * family, so the family-scoped ChatGPT path leaves it out of the single-family draft and keeps it on merge.
 */
const CARRIED_FAMILY_MAPPING_ID=/^family-\d+-carried-\d+$/u;
export const carriedFamilyMappingId=(family:number,n:number)=>'family-'+String(family)+'-carried-'+String(n);
export const isCarriedFamilyMapping=(rule:MappingRule)=>CARRIED_FAMILY_MAPPING_ID.test(rule.id);
export function validateEventProfiles(config?:EventProfileConfig):string|null{
 if(!config)return null;
 if(!(safe(config.discriminator)||config.discriminator===READING_FAMILY_DISCRIMINATOR)||config.unknown!=='reject'||
   config.variants.length<2||config.variants.length>16)return 'Invalid event family selector.';
 const ids=new Set<string>(),values=new Set<string>();
 for(const p of config.variants){
   if(!/^[a-z][a-z0-9_-]{0,31}$/.test(p.name)||ids.has(p.name)||
     !p.equals||p.equals.length>128||/[\x00-\x1f\x7f]/.test(p.equals)||values.has(p.equals)||
     p.mappings.length>100)return 'Invalid or duplicate event family.';
   ids.add(p.name);values.add(p.equals);
   for(const m of p.mappings)if(!safe(m.source)||!safe(m.target))
     return 'Invalid event-specific field path.';
 }
 return null;
}
