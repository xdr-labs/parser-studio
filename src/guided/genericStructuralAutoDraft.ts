import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {MAX_EVENTS,preview,splitEvents} from '../parser';
import {extractGenericStructural,type GenericStructuralProfile} from '../genericStructural';
import {GENERIC_STRUCTURAL_PROFILES,GENERIC_STRUCTURAL_MIXED_PROFILE_V1} from '../genericStructuralProfiles';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {defaultGuidedOptions,type FieldGroup} from './contract';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import {originalContainerCompilerGate} from './sourceContainerCompilerGate';
import {vendorFieldNames} from './vendorFieldNames';
import {carriedFamilyMappingId,validateEventProfiles,type EventProfile} from './multiEventRouting';
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

  // An explicit profile combination keeps one reviewed mapping set: its recipe has no event-family routing.
  const routed=discovery.profile?null:familyRoutedDraft(source,candidate,candidateSuite,GENERIC_MODE_FAMILIES);
  if(routed)return {draft:routed.draft,suite:routed.suite,automaticOfficialMappings:routed.official};
  return {draft:candidate,suite:candidateSuite,
    automaticOfficialMappings:suggestions.length};
}


/**
 * Event families of one sample that read the same Stellar meaning from different source paths (audit G-09:
 * PAN-OS generic.fields.src beside CEF body.src). One shared mapping per destination cannot serve both, and the
 * candidate engine rightly refuses to pick one of two plausible sources, so neither family got the official
 * field. Here the events are grouped by the reading mode the grammar records for every event (generic.mode),
 * the official candidates are decided inside each group, and each family gets its own mappings through the
 * reviewed event-profile contract (one destination at most once per event, different families may reuse it).
 * A mapping whose decision is the same for every family stays shared. An event of a family that was not in the
 * sample is not parsed with the mappings of another family: the event-profile contract reports it
 * (UNRECOGNIZED_EVENT_FAMILY), and the generated parser keeps its original text in parser_raw_msg.
 * The routed draft is used only when it maps strictly more official values than the shared draft.
 * A mixed parser is routed the same way by the family its router read each event with (@reading_family):
 * autoParserDraft.ts, the Auto Parser path for a sample of several allowlisted one-line families.
 */
export interface EventFamilyRouting{
  /** eventProfiles discriminator of the routed draft. */
  discriminator:string;
  /** The family of a preview event, or undefined when it has none (no routing then). */
  familyOf:(event:SuiteResult['events'][number])=>string|undefined;
  /**
   * Whether each family carries the sources that only other families of the sample showed (as vendor text). A
   * mixed parser emits mapped sources only, so it must (independent audit 2026-11-23, F1). A Generic Structural
   * parser keeps every field it read in parserstudio_source, so a carried mapping would add nothing there.
   */
  carryOtherFamilySources:boolean;
}
const GENERIC_MODE_FAMILIES:EventFamilyRouting={discriminator:'generic.mode',carryOtherFamilySources:false,familyOf:event=>{
  const mode=lookupFieldValue(event.fields,'generic.mode');
  return mode.found&&typeof mode.value==='string'?mode.value:undefined;
}};
const FAMILY_NAME=/^[a-z][a-z0-9_-]{0,31}$/u;
type Decision={target:string;type:MappingRule['type'];group:FieldGroup};

function officialValues(suite:SuiteResult,vendor:string):number{
  let count=0;
  for(const event of suite.events){
    const out=(event.normalized??{}) as Record<string,unknown>;
    for(const key of Object.keys(out))
      if(!key.startsWith('parserstudio_')&&key!==vendor)count++;
  }
  return count;
}

export function familyRoutedDraft(
  source:string,candidate:ParserDraft,suite:SuiteResult,routing:EventFamilyRouting,
):{draft:ParserDraft;suite:SuiteResult;official:number}|null{
  // A conditional mapping (`when`) already decides per event; routing it again could map one source twice.
  if(candidate.eventProfiles||candidate.mappings.some(mapping=>mapping.when))return null;
  const families=new Map<string,number[]>();
  for(const [index,event] of suite.events.entries()){
    const family=routing.familyOf(event);
    if(family===undefined||!FAMILY_NAME.test(family))return null;
    families.set(family,[...(families.get(family)??[]),index]);
  }
  if(families.size<2||families.size>16)return null;
  const names=[...families.keys()].sort();
  const vendorMappings=new Map(candidate.mappings.map(mapping=>[mapping.source,mapping]));
  const decisions=new Map<string,Map<string,Decision|null>>();
  for(const name of names){
    const events=families.get(name)!.map(index=>suite.events[index]!);
    const present=new Set(events.flatMap(event=>listSafeLeafPaths(event.fields)));
    const decided=new Map<string,Decision|null>();
    for(const mapping of candidate.mappings)if(present.has(mapping.source))decided.set(mapping.source,null);
    // Only the mappings of this family are its taken destinations: the vendor name another family keeps
    // (generic.kv.srcip as vendor "srcip") does not block body.src -> srcip here (golden mixed_envelope_cef_kv).
    const high=suggestNormalizationCandidatesFromSuite({...suite,events},
      candidate.mappings.filter(mapping=>present.has(mapping.source)).map(mapping=>vendorMappings.get(mapping.source)!),{})
      .filter(item=>item.confidence==='HIGH');
    for(const item of high)if(decided.has(item.source))
      decided.set(item.source,{target:item.target,type:item.type,group:item.group});
    decisions.set(name,decided);
  }
  const same=(a:Decision|null|undefined,b:Decision|null|undefined)=>
    (a??null)===null?(b??null)===null:!!b&&a!.target===b.target&&a!.type===b.type&&a!.group===b.group;
  const apply=(mapping:MappingRule,decision:Decision|null,id:string):[MappingRule,FieldGroup]=>decision
    ?[{...mapping,id,target:decision.target,type:decision.type},decision.group]
    :[{...mapping,id},'vendor_fields'];
  const groups:Record<string,FieldGroup>={};
  const shared:MappingRule[]=[];
  const local=new Set<string>();
  for(const mapping of candidate.mappings){
    const perFamily=names.map(name=>decisions.get(name)!);
    const everywhere=perFamily.every(decided=>decided.has(mapping.source));
    const first=perFamily[0]!.get(mapping.source);
    if(everywhere&&perFamily.every(decided=>same(decided.get(mapping.source),first))){
      const [rule,group]=apply(mapping,first??null,mapping.id);
      shared.push(rule);groups[rule.id]=group;
    }else local.add(mapping.source);
  }
  const variants:EventProfile[]=names.map((name,index)=>{
    const decided=decisions.get(name)!;
    const mappings:MappingRule[]=[];
    let n=0;
    for(const mapping of candidate.mappings){
      // Every family keeps every source that a family mapping names, as a vendor field where its own records did
      // not decide an official one: an event of this family may carry a key the sample showed only in another
      // family, and a mixed parser emits mapped sources only (independent audit 2026-11-23, F1: user=alice and a
      // second srcip were dropped from FULL events). A source the records of this family do not have is carried
      // when the routing needs it (carryOtherFamilySources). The container of a source is no test of whether an
      // event of the family can hold it: a JSON family whose sample has nested keys only can still carry a root
      // key at run time (re-audit 2026-11-23, Q2-1).
      if(!local.has(mapping.source))continue;
      const carried=!decided.has(mapping.source);
      if(carried&&!routing.carryOtherFamilySources)continue;
      const id=carried?carriedFamilyMappingId(index,n++):'family-'+String(index)+'-'+String(n++);
      const [applied,group]=apply(mapping,decided.get(mapping.source)??null,id);
      // A carried source keeps its text: its type was inferred from the values of another family, and a key=value
      // or JSON event of this family may hold any text under that key (re-audit 2026-11-23, Q2-2: bytes=007 lost its
      // leading zeros, bytes=abc failed the event).
      const rule=carried?{...applied,type:'string' as const}:applied;
      mappings.push(rule);groups[rule.id]=group;
    }
    return {name,equals:name,mappings};
  });
  if(!variants.some(variant=>variant.mappings.length>0))return null;
  const eventProfiles={discriminator:routing.discriminator,unknown:'reject' as const,variants};
  if(validateEventProfiles(eventProfiles)!==null)return null;
  // One destination at most once per event: the shared outputs and the outputs of one family.
  const output=(rule:MappingRule)=>(groups[rule.id]==='vendor_fields'?'\u0000vendor.':'')+rule.target;
  const overlaps=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
  for(const variant of variants){
    const seen:string[]=[];
    for(const rule of [...shared,...variant.mappings]){
      const out=output(rule);
      if(seen.some(other=>overlaps(other,out)))return null;
      seen.push(out);
    }
  }
  const routed:ParserDraft={...candidate,mappings:shared,eventProfiles,
    guided:{...candidate.guided!,groups}};
  const routedSuite=preview(source,routed);
  if(routedSuite.counts.total!==suite.counts.total||routedSuite.counts.matched!==routedSuite.counts.total||
     routedSuite.counts.extracted!==routedSuite.counts.total||routedSuite.counts.normalized!==routedSuite.counts.total||
     routedSuite.counts.failures!==0)return null;
  const vendor=candidate.vendor.trim();
  if(officialValues(routedSuite,vendor)<=officialValues(suite,vendor))return null;
  const official=[...shared,...variants.flatMap(variant=>variant.mappings)]
    .filter(rule=>groups[rule.id]!=='vendor_fields').length;
  return {draft:routed,suite:routedSuite,official};
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
const NAMED_POSITIONAL_MODES:readonly string[]=['panos_traffic_csv','panos_threat_csv','panos_system_csv'];

/**
 * Readings that keep the cells of a delimited record and take the name of every cell from the record itself
 * (each cell is key=value).
 */
const KEYED_CELL_MODES:readonly string[]=['delimited_kv'];

/**
 * The events the first scan takes for a delimited record without an envelope, whether the strict CSV lexer
 * could read the line or not. The status is not asked: one double quote inside a cell makes the lexer fail
 * (BODY_MALFORMED), and treating such a line as free for any reading let a reading that merges three cells
 * into the last key=value value be adopted as completely parsed (independent audit 2026-11-21, F-01). What
 * such an event is adopted with is decided on the reading (buildSourceReviewedBoundedDraft).
 */
export function headerlessCsvEvents(
  entries:readonly {envelope:string;body:string;status:string}[],
):boolean[]{
  return entries.map(entry=>entry.envelope==='none'&&entry.body==='csv');
}

/** The events the first scan read natively: recognized, and not a delimited record without column names. */
export function nativelyReadEvents(
  entries:readonly {envelope:string;body:string;status:string}[],
):boolean[]{
  return entries.map(entry=>entry.status==='RECOGNIZED'&&!(entry.envelope==='none'&&entry.body==='csv'));
}

const PROVENANCE_COPIES:readonly string[]=['source_raw','message_raw'];
const isRecord=(value:unknown):value is Record<string,unknown>=>
  value!==null&&typeof value==='object'&&!Array.isArray(value);

/** Every leaf of a reading with the name of the field that holds it; the copies of the original text are not fields. */
function leavesByName(value:unknown,name:string,out:Map<string,string[]>):void{
  if(Array.isArray(value)){for(const child of value)leavesByName(child,name,out);return;}
  if(isRecord(value)){
    for(const [key,child] of Object.entries(value))if(!PROVENANCE_COPIES.includes(key))leavesByName(child,key,out);
    return;
  }
  if(value===undefined||value===null)return;
  const list=out.get(name);
  if(list)list.push(String(value));else out.set(name,[String(value)]);
}

/** The cells of a line: cut at the delimiter outside double quotes (a backslash keeps a quote inside its value). */
function topLevelCells(raw:string,delimiter:string):string[]{
  const cells:string[]=[];
  let start=0,quoted=false;
  for(let index=0;index<raw.length;index+=1){
    const ch=raw[index]!;
    if(quoted&&ch==='\\'){index+=1;continue;}
    if(ch==='"'){quoted=!quoted;continue;}
    if(!quoted&&ch===delimiter){cells.push(raw.slice(start,index));start=index+1;}
  }
  cells.push(raw.slice(start));
  return cells;
}

// A positional piece of a reading (a prefix token, a Syslog header field) that holds cells of a delimited
// record: "10:00:00,web01,request", "10:00:00|web01|request", "10:00:00,web01". The decimal fraction of a time,
// which ISO 8601 writes with a comma as well ("10:00:00,123", "10:00:00,123+09:00"), is not a second cell
// (independent audit 2026-11-22, G-03: pipes and two cells were not seen).
const SECOND_FRACTION=/^\d+(?:Z|[+-]\d{2}(?::?\d{2})?)?$/u;
const cellDelimiters=(piece:string):string[]=>
  [',',';','|'].filter(delimiter=>{
    const parts=piece.split(delimiter).filter(part=>part.length>0);
    return parts.length>=3||(parts.length===2&&!SECOND_FRACTION.test(parts[1]!));
  });

/**
 * True when a positional piece of the reading holds the cells of a delimited record: the reading cut the line
 * at white space although its header is separated by commas, semicolons or pipes, so what it calls one field is
 * several cells. Values of key=value pairs are not asked here: "flags=SYN,ACK" is one value.
 */
function mergesDelimitedCells(fields:Record<string,unknown>):boolean{
  const pieces:unknown[]=[];
  const generic=fields.generic;
  if(isRecord(generic)){
    for(const [key,value] of Object.entries(generic))if(/^prefix_\d+$/u.test(key))pieces.push(value);
    if(Array.isArray(generic.prefix_tokens))pieces.push(...generic.prefix_tokens);
  }
  // The header fields of the Syslog envelope; a copy of original text the reader keeps beside them
  // (structured_data_raw) is not a positional piece, and its quoted values may hold any character.
  if(isRecord(fields.syslog))
    for(const [key,value] of Object.entries(fields.syslog))if(!key.endsWith('_raw'))pieces.push(value);
  // A header whose cells are separated by pipes stands before the pairs of a CEF or LEEF record ("CEF: 0|Vendor|
  // Product|..." read as positional pieces): pipes in a positional piece alone do not show a merged record. A
  // pair value of the same reading that holds a pipe as well does ("url=/index.html|10.0.0.9|8443|ok").
  const pairValues=new Map<string,string[]>();
  if(isRecord(generic))for(const value of Object.values(generic))if(isRecord(value))leavesByName(value,'',pairValues);
  const pipeInValue=[...pairValues.values()].some(list=>list.some(value=>value.includes('|')));
  return pieces.some(piece=>typeof piece==='string'&&
    cellDelimiters(piece).some(delimiter=>delimiter!=='|'||pipeInValue));
}

/** True when every value of a keyed reading lies inside one cell of the line it was read from. */
function keepsCells(raw:string,generic:Record<string,unknown>):boolean{
  const delimiter=typeof generic.delimiter==='string'&&generic.delimiter.length===1?generic.delimiter:',';
  const cells=topLevelCells(raw,delimiter);
  const values=new Map<string,string[]>();
  leavesByName(generic.fields,'',values);
  for(const list of values.values())
    for(const value of list)
      if(value.includes(delimiter)&&!cells.some(cell=>cell.includes(value)))return false;
  return true;
}

/**
 * True when the compiler's reading of an event holds everything its native reading holds: every field of the
 * native event body under the same name with the same value, and the Syslog host as a host name. Asked only
 * for an event the native reader reads completely; a native reading that is not FULL has nothing to protect.
 */
function keepsNativeReading(raw:string,draft:ParserDraft,fields:Record<string,unknown>):boolean{
  const native=preview(raw,{...draft,format:'auto'}).events[0];
  if(!native||native.parseStatus!=='FULL')return true;
  const read=new Map<string,string[]>();
  leavesByName(fields,'',read);
  const body=isRecord(native.fields.body)?native.fields.body
    :Object.fromEntries(Object.entries(native.fields).filter(([key])=>!key.startsWith('syslog_')));
  const expected=new Map<string,string[]>();
  leavesByName(body,'',expected);
  for(const [name,list] of expected){
    const found=[...(read.get(name)??[])];
    for(const value of list){
      const at=found.indexOf(value);
      if(at<0)return false;
      found.splice(at,1);
    }
  }
  const host=native.fields.syslog_hostname;
  return typeof host!=='string'||(read.get('hostname')??[]).includes(host);
}

/** Reading modes that keep the text of the event as one message. The modes that extract key=value pairs
 * (space_kv, syslog_prefix_kv) are not judged here: both hold every pair under generic.kv.*, and the boundary
 * between them (a text prefix with two to four pairs, five pairs or more) is the one of the shared grammar. */
const MESSAGE_MODES:readonly string[]=['bsd_tagged_message','bsd_bracket_pid_message','bsd_classic_pid_message'];
// A pair starts the text or follows white space, a semicolon or a comma (final audit F-2: `a=1;b=2 word`).
const PAIR_AT_TOKEN_START=/(?:^|[\s;,])[A-Za-z_][\w.-]*=\S/gu;

/**
 * True when the reading keeps key=value pairs of the event as message text: it holds the text, it has not parsed
 * the pairs (owner decision of 2026-11-25: keeping the original message and structural parsing are two things).
 * Prose with one such token ("session closed for uid=1001") is text.
 */
function keepsPairsAsText(generic:Record<string,unknown>):boolean{
  return MESSAGE_MODES.includes(String(generic.mode))&&typeof generic.message==='string'&&
    (generic.message.match(PAIR_AT_TOKEN_START)??[]).length>=2;
}

/**
 * True when an event kept as message text is read the same way with one more key=value pair at its end: the same
 * reading mode, and every value still under its name, unchanged or longer at its end (a message grows by the
 * pair). A message that becomes key=value fields with one more pair would change every path at run time.
 */
function staysWithOneMorePair(raw:string,draft:ParserDraft,fields:Record<string,unknown>):boolean{
  const generic=fields.generic;
  if(!isRecord(generic)||!MESSAGE_MODES.includes(String(generic.mode)))return true;
  const probe=preview(raw+' parserstudio_probe=1',draft).events[0];
  const again=probe?.fields.generic;
  if(!probe||!isRecord(again)||again.mode!==generic.mode)return false;
  const before=new Map<string,string[]>(),after=new Map<string,string[]>();
  leavesByName(fields,'',before);leavesByName(probe.fields,'',after);
  for(const [name,list] of before){
    const next=after.get(name)??[];
    if(list.some((value,index)=>next[index]===undefined||!next[index]!.startsWith(value)))return false;
  }
  return true;
}

/**
 * Adoption of the bounded compiler's reading, decided on the reading of each event.
 *
 * A delimited record - an event the first scan takes for one (`headerlessCsv[i]`), or one whose reading holds
 * several cells in a positional piece - is adopted only with a reading that keeps its cells AND has names for
 * them: from a verified record layout, or from the record itself when every cell is key=value. Any other
 * reading of that line (a Syslog header taken from the first cells, key=value pairs taken from one cell with
 * the last value running over the following cells) moves the cell boundaries of the record.
 *
 * An event the first scan read natively (`nativelyRead[i]`) is adopted only with a reading that holds
 * everything its native reading holds (independent audit 2026-11-21, F-02): one draft replaces the reading of
 * every event of the sample, and a completely read Syslog key=value line must not become one message field
 * because a line beside it needed the compiler.
 *
 * No event is adopted with a reading that keeps its key=value pairs as message text (keepsPairsAsText), or with
 * a message reading that one more key=value pair would move to another reading mode (staysWithOneMorePair): such
 * an event stays with the first scan, which asks for a rule.
 *
 * This holds whichever events of the sample opened the route.
 */
export function buildSourceReviewedBoundedDraft(
  source:string,draft:ParserDraft,review:GenericStructuralSourceReview,headerlessCsv:readonly boolean[],
  nativelyRead:readonly boolean[]=[],
):ReturnType<typeof buildAutomaticGenericStructuralDraft>{
  const candidate=buildSourceReviewedGenericStructuralDraft(source,draft,review);
  if(!candidate)return null;
  const count=candidate.suite.events.length;
  if(headerlessCsv.length!==count&&headerlessCsv.some(Boolean))return null;
  if(nativelyRead.length!==count&&nativelyRead.some(Boolean))return null;
  return candidate.suite.events.every((event,index)=>{
    const generic=event.fields.generic;
    if(headerlessCsv[index]===true||mergesDelimitedCells(event.fields)){
      if(!isRecord(generic))return false;
      const mode=String(generic.mode);
      if(!NAMED_POSITIONAL_MODES.includes(mode)&&!(KEYED_CELL_MODES.includes(mode)&&keepsCells(event.raw,generic)))return false;
    }
    if(isRecord(generic)&&keepsPairsAsText(generic))return false;
    if(!staysWithOneMorePair(event.raw,candidate.draft,event.fields))return false;
    return nativelyRead[index]!==true||keepsNativeReading(event.raw,draft,event.fields);
  })?candidate:null;
}

/** A sample in which the first scan read every event as positional CSV without column names. */
export function buildSourceReviewedNamedPositionalDraft(
  source:string,draft:ParserDraft,review:GenericStructuralSourceReview,
):ReturnType<typeof buildAutomaticGenericStructuralDraft>{
  return buildSourceReviewedBoundedDraft(source,draft,review,review.events.map(()=>true));
}
