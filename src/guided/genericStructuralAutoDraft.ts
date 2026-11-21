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
/** A new Generic Structural parser reads CEF/LEEF lines with the dedicated grammar or declines them (D-2). */
const FAMILY_GRAMMAR='dedicated' as const;
// What the reading says about itself, not a value of the event: which grammar route read the line, with which
// separator and profile, which Syslog header variant matched and how strictly. These stay in the source container
// (parserstudio_source) and never become a vendor field: `variant="rfc3164"` or `confidence="strict"` beside the
// fields of a firewall record would be output the device did not send.
const NON_DATA_PATHS=new Set([
  'generic.mode','generic.delimiter','generic.profile','syslog.variant','syslog.confidence',
]);

function sourcePaths(source:string,draft:ParserDraft):{paths:string[];profile?:GenericStructuralProfile}|null{
  const boundary=draft.guided?.eventBoundary??'single-line';
  if(boundary!=='single-line')return null;
  const records=splitEvents(source,boundary,MAX_EVENTS+1);
  if(!records.length||records.length>MAX_EVENTS)return null;
  // The draft built from these paths always reads CEF/LEEF lines with the dedicated grammar (owner policy D-2), so
  // the paths are discovered with the same grammar. Discovering them with the earlier reading named fields
  // (generic.kv.*) that the preview and the generated parser never produce for such a line: every automatic mapping
  // pointed at nothing and no recommended Stellar match could be applied to it.
  const extract=(raw:string,candidate?:GenericStructuralProfile)=>extractGenericStructural(raw,candidate,FAMILY_GRAMMAR);
  const legacy=records.map(record=>extract(record.raw));
  // Prefer one existing profile when it supports every record. Only the explicit
  // versioned combination may select both additional grammars in one project.
  const ownsLeefFamily=records.some(record=>record.raw.startsWith('LEEF:2.0|'));
  const candidates:readonly GenericStructuralProfile[]=ownsLeefFamily
    ?['leef2_implicit_tab',GENERIC_STRUCTURAL_MIXED_PROFILE_V1]:GENERIC_STRUCTURAL_PROFILES;
  const needsProfile=ownsLeefFamily||legacy.some(extracted=>extracted.errors.length>0);
  const profile=needsProfile?candidates.find(candidate=>records.every(record=>
    extract(record.raw,candidate).errors.length===0)):undefined;
  if(needsProfile&&!profile)return null;
  const all=new Set<string>();
  for(const [index,record] of records.entries()){
    const extracted=profile?extract(record.raw,profile):legacy[index]!;
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
  // A new parser: CEF/LEEF lines are read by the dedicated grammar or declined (owner policy D-2).
  candidate.genericStructuralFamilyGrammar=FAMILY_GRAMMAR;
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

/** Readings that name the columns of a positional record from a verified record layout. */
const NAMED_POSITIONAL_MODES:readonly string[]=['panos_traffic_csv'];

/**
 * The events the first scan READ as positional CSV without an envelope. An event it only suspected to be CSV
 * and could not read (BODY_MALFORMED: comma-separated key="value" pairs behind a Syslog tag, for example) is an
 * unsupported event; the bounded compiler is free to read it.
 */
export function headerlessCsvEvents(
  entries:readonly {envelope:string;body:string;status:string}[],
):boolean[]{
  return entries.map(entry=>entry.envelope==='none'&&entry.body==='csv'&&entry.status==='RECOGNIZED');
}

/**
 * Adoption of the bounded compiler's reading against what the first scan said about each event.
 * `headerlessCsv[i]` is true for an event the first scan read as positional CSV without column names. Such an
 * event is adopted only with a reading that names the columns from a verified record layout. Any other reading
 * of that line (a Syslog header taken from the first cells, key=value pairs taken from one cell) would move the
 * cell boundaries the CSV reading already has. This holds whichever events of the sample opened the route: a
 * sample with one unsupported line does not make the CSV lines beside it free text.
 */
export function buildSourceReviewedBoundedDraft(
  source:string,draft:ParserDraft,review:GenericStructuralSourceReview,headerlessCsv:readonly boolean[],
):ReturnType<typeof buildAutomaticGenericStructuralDraft>{
  const candidate=buildSourceReviewedGenericStructuralDraft(source,draft,review);
  if(!candidate)return null;
  if(headerlessCsv.length!==candidate.suite.events.length)return headerlessCsv.some(Boolean)?null:candidate;
  return candidate.suite.events.every((event,index)=>{
    if(!headerlessCsv[index])return true;
    const generic=event.fields.generic;
    return !!generic&&typeof generic==='object'&&!Array.isArray(generic)&&
      NAMED_POSITIONAL_MODES.includes(String((generic as Record<string,unknown>).mode));
  })?candidate:null;
}

/** A sample in which the first scan read every event as positional CSV without column names. */
export function buildSourceReviewedNamedPositionalDraft(
  source:string,draft:ParserDraft,review:GenericStructuralSourceReview,
):ReturnType<typeof buildAutomaticGenericStructuralDraft>{
  return buildSourceReviewedBoundedDraft(source,draft,review,review.events.map(()=>true));
}
