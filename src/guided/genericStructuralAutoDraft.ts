import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {MAX_EVENTS,preview,splitEvents} from '../parser';
import {extractGenericStructural} from '../genericStructural';
import {listSafeLeafPaths} from '../fieldPaths';
import {defaultGuidedOptions,type FieldGroup} from './contract';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

const MAX_EXPLICIT_MAPPINGS=60;
const NON_DATA_PATHS=new Set([
  'generic.mode','generic.delimiter',
]);

function sourcePaths(source:string,draft:ParserDraft):string[]|null{
  const boundary=draft.guided?.eventBoundary??'single-line';
  if(boundary!=='single-line')return null;
  const records=splitEvents(source,boundary,MAX_EVENTS+1);
  if(!records.length||records.length>MAX_EVENTS)return null;
  const all=new Set<string>();
  for(const record of records){
    const extracted=extractGenericStructural(record.raw);
    if(extracted.errors.length)return null;
    for(const path of listSafeLeafPaths(extracted.fields)){
      if(NON_DATA_PATHS.has(path)||path.endsWith('.source_raw'))continue;
      all.add(path);
    }
  }
  return [...all];
}

function targetForVendorSource(source:string):string{
  // Preserve the JSON-like source path for vendor-only fields. The backend
  // adds the selected parser vendor namespace at emission time.
  return source;
}

/**
 * Beginner-mode automatic handoff for a fully source-parsed Generic Structural
 * sample. This is the same action that the old "Use extracted fields" button
 * performed, but it now prepares every safe source field (bounded at the
 * compiler mapping limit) and upgrades trustworthy dictionary matches.
 */
export function buildAutomaticGenericStructuralDraft(
  source:string,draft:ParserDraft,
):{draft:ParserDraft;suite:SuiteResult;automaticOfficialMappings:number}|null{
  if(draft.format!=='auto')return null;
  const paths=sourcePaths(source,draft);
  if(!paths?.length)return null;

  const opts=draft.guided??defaultGuidedOptions();
  const initialPaths=paths.slice(0,MAX_EXPLICIT_MAPPINGS);
  const mappings:MappingRule[]=initialPaths.map((sourcePath,index)=>({
    id:'auto-generic-'+String(index+1),
    source:sourcePath,
    target:targetForVendorSource(sourcePath),
    type:'string',
  }));
  const groups:Record<string,FieldGroup>=Object.fromEntries(
    mappings.map(mapping=>[mapping.id,'vendor_fields' as const]),
  );
  let candidate:ParserDraft={
    ...draft,
    format:'generic_structural',
    mappings,
    guided:{...opts,enrichment:[],groups,
      classification:{defaultIndex:'Syslog',rules:[]}},
  };
  let candidateSuite=preview(source,candidate);

  const suggestions=suggestNormalizationCandidatesFromSuite(
    candidateSuite,candidate.mappings,candidate.guided?.groups??{},
  ).filter(item=>item.confidence==='HIGH');

  if(suggestions.length){
    const bySource=new Map(suggestions.map(item=>[item.source,item]));
    const nextGroups={...(candidate.guided?.groups??{})};
    const nextMappings=candidate.mappings.map(mapping=>{
      const suggested=bySource.get(mapping.source);
      if(!suggested)return mapping;
      nextGroups[mapping.id]=suggested.group;
      return {...mapping,target:suggested.target,type:suggested.type};
    });
    candidate={...candidate,mappings:nextMappings,
      guided:{...candidate.guided!,groups:nextGroups}};
    candidateSuite=preview(source,candidate);
  }

  if(candidateSuite.counts.total===0||
     candidateSuite.counts.matched!==candidateSuite.counts.total||
     candidateSuite.counts.extracted!==candidateSuite.counts.total||
     candidateSuite.counts.failures!==0)return null;

  return {draft:candidate,suite:candidateSuite,
    automaticOfficialMappings:suggestions.length};
}
