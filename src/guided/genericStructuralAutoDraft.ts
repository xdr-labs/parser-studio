import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {MAX_EVENTS,preview,splitEvents} from '../parser';
import {extractGenericStructural,type GenericStructuralProfile} from '../genericStructural';
import {GENERIC_STRUCTURAL_PROFILES,GENERIC_STRUCTURAL_MIXED_PROFILE_V1} from '../genericStructuralProfiles';
import {listSafeLeafPaths} from '../fieldPaths';
import {defaultGuidedOptions,type FieldGroup} from './contract';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import {originalContainerCompilerGate} from './sourceContainerCompilerGate';
import {vendorFieldNames} from './vendorFieldNames';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

const MAX_EXPLICIT_MAPPINGS=100;
const NON_DATA_PATHS=new Set([
  'generic.mode','generic.delimiter',
]);

function sourcePaths(source:string,draft:ParserDraft):{paths:string[];profile?:GenericStructuralProfile}|null{
  const boundary=draft.guided?.eventBoundary??'single-line';
  if(boundary!=='single-line')return null;
  const records=splitEvents(source,boundary,MAX_EVENTS+1);
  if(!records.length||records.length>MAX_EVENTS)return null;
  const legacy=records.map(record=>extractGenericStructural(record.raw));
  // Prefer one existing profile when it supports every record. Only the explicit
  // versioned combination may select both additional grammars in one project.
  const ownsLeefFamily=records.some(record=>record.raw.startsWith('LEEF:2.0|'));
  const candidates:readonly GenericStructuralProfile[]=ownsLeefFamily
    ?['leef2_implicit_tab',GENERIC_STRUCTURAL_MIXED_PROFILE_V1]:GENERIC_STRUCTURAL_PROFILES;
  const needsProfile=ownsLeefFamily||legacy.some(extracted=>extracted.errors.length>0);
  const profile=needsProfile?candidates.find(candidate=>records.every(record=>
    extractGenericStructural(record.raw,candidate).errors.length===0)):undefined;
  if(needsProfile&&!profile)return null;
  const all=new Set<string>();
  for(const [index,record] of records.entries()){
    const extracted=profile?extractGenericStructural(record.raw,profile):legacy[index]!;
    if(extracted.errors.length)return null;
    for(const path of listSafeLeafPaths(extracted.fields)){
      if(NON_DATA_PATHS.has(path)||path.endsWith('.source_raw'))continue;
      all.add(path);
    }
  }
  return {paths:[...all],...(profile?{profile}:{})};
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
  // The backend adapter accepts a declared relay profile only on relay-capable
  // formats, and Generic Structural is not one of them. Adopting it here would
  // report a complete parse and then lock Map Fields, so leave the sample in the
  // review-required path instead.
  if(draft.forwarder)return null;
  const discovery=sourcePaths(source,draft);
  if(!discovery?.paths.length||
    (discovery.profile&&discovery.paths.length>MAX_EXPLICIT_MAPPINGS))return null;

  const opts=draft.guided??defaultGuidedOptions();
  const initialPaths=discovery.paths.slice(0,MAX_EXPLICIT_MAPPINGS);
  const vendorNames=vendorFieldNames(initialPaths);
  if(vendorNames.size!==initialPaths.length)return null;
  const mappings:MappingRule[]=initialPaths.map((sourcePath,index)=>({
    id:'auto-generic-'+String(index+1),
    authoring:{version:1,origin:'AUTO'},
    source:sourcePath,
    target:vendorNames.get(sourcePath)!,
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
  if(discovery.profile)candidate.genericStructuralProfile=discovery.profile;
  else delete candidate.genericStructuralProfile;
  let candidateSuite=preview(source,candidate);

  const suggestions=suggestNormalizationCandidatesFromSuite(
    candidateSuite,candidate.mappings,candidate.guided?.groups??{},
    {skipAmbiguousTargets:discovery.profile===GENERIC_STRUCTURAL_MIXED_PROFILE_V1},
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

export interface GenericStructuralSourceReview {
  raw:string;
  metadataLines?:number;
  transportFramingParts?:number;
  events:readonly {
    startByte:number;endByte:number;
    preview:Pick<MultiPassSourcePreview,'status'|'issues'>;
  }[];
}

/**
 * Adopt a bounded compiler result only against the same reviewed source records.
 * A strict additional grammar may resolve a partial diagnostic preview; legacy
 * routes still require the preview to be complete. Neither path drops framing.
 */
export function buildSourceReviewedGenericStructuralDraft(
  source:string,draft:ParserDraft,review:GenericStructuralSourceReview,
):ReturnType<typeof buildAutomaticGenericStructuralDraft>{
  if(review.raw!==source||review.metadataLines||review.transportFramingParts||
     originalContainerCompilerGate(source,review))return null;
  const candidate=buildAutomaticGenericStructuralDraft(source,draft);
  if(!candidate||candidate.suite.events.length!==review.events.length||
     candidate.suite.counts.normalized!==candidate.suite.counts.total)return null;
  const bytes=new TextEncoder().encode(source);
  const decoder=new TextDecoder('utf-8',{fatal:true});
  let previousEnd=0;
  for(const [index,event] of candidate.suite.events.entries()){
    const witness=review.events[index]!;
    if(!Number.isInteger(witness.startByte)||!Number.isInteger(witness.endByte)||
       witness.startByte<previousEnd||witness.endByte<=witness.startByte||
       witness.endByte>bytes.length)return null;
    try{
      if(decoder.decode(bytes.slice(witness.startByte,witness.endByte))!==event.raw)return null;
    }catch{return null;}
    previousEnd=witness.endByte;
    if(witness.preview.status==='SOURCE_PARSED')continue;
    const generic=event.fields.generic;
    if(witness.preview.status!=='PARTIAL'||!candidate.draft.genericStructuralProfile||
       !generic||typeof generic!=='object'||Array.isArray(generic)||
       !['syslog_prefix_kv','leef2_implicit_tab'].includes(
         String((generic as Record<string,unknown>).mode)))return null;
  }
  return candidate;
}
