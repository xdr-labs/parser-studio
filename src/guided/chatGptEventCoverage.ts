/** Describe only evidence supplied in original log records and current browser
 * preview. This is NOT a manufacturer semantic oracle, an AI model or a new
 * extraction grammar. It never repairs or alters the source bytes.
 */
import type {ParserDraft,SuiteResult} from '../model';
import {lookupFieldValue,listSafeLeafPaths,safeLocalFieldPath} from '../fieldPaths';
import {MAX_EVENTS,splitEvents} from '../parser';

const SELECTORS=['type','subtype','event_type','eventtype','eventType','category','log_type'] as const;
const MAX_KINDS=16,MAX_FIELDS=24,MAX_MAPPINGS=24;
type ObservedKind={selector:string;records:number};
type ProtectedMapping={source:string;target:string;group:'top_fields'|'ns_fields'|'vendor_fields';type:string;observedRecords:number};

export interface EventCoverageEvidence{
  text:string;
  sourceRecords:number;
  observedKinds:number;
  unclassifiedRecords:number;
  protectedMappings:number;
}

function safeLiteral(value:unknown):string|null{
  if(typeof value!=='string'&&typeof value!=='number')return null;
  const text=String(value);
  return text.length>=1&&text.length<=64&&/^[A-Za-z0-9_.:/-]+$/.test(text)?text:null;
}
function discoveredSelector(raw:string):string|null{
  const trimmed=raw.trimStart();
  if(trimmed.startsWith('{')){
    try{
      const parsed=JSON.parse(trimmed) as unknown;
      if(parsed&&typeof parsed==='object'&&!Array.isArray(parsed)){
        const fields=parsed as Record<string,unknown>;
        const pairs:string[]=[];
        for(const key of SELECTORS){
          const value=safeLiteral(fields[key]);
          if(value!==null)pairs.push(key+'='+value);
        }
        if(pairs.length)return pairs.slice(0,3).join(' ');
        const action=safeLiteral(fields.action);
        if(action!==null)return 'action='+action;
      }
    }catch{/* Malformed source is never treated as a valid JSON event. */}
  }
  if(trimmed.startsWith('CEF:')){
    const parts=trimmed.split('|');
    const signature=safeLiteral(parts[4]);
    if(parts.length>=7&&signature)return 'CEF signature='+signature;
  }
  if(trimmed.startsWith('LEEF:')){
    const parts=trimmed.split('|');
    const eventId=safeLiteral(parts[4]);
    if(parts.length>=5&&eventId)return 'LEEF eventId='+eventId;
  }
  const selectors:Record<string,string>=Object.create(null);
  const kv=/(?:^|\s)(type|subtype|event_type|eventtype|category|log_type|action)=(?:"([^"\r\n]{1,64})"|([^\s"'\r\n]{1,64}))/gi;
  for(const token of raw.matchAll(kv)){
    const key=token[1]!.toLowerCase(),value=safeLiteral(token[2]??token[3]);
    if(value!==null&&!Object.prototype.hasOwnProperty.call(selectors,key))
      selectors[key]=value;
  }
  const pairs=SELECTORS.map(key=>key.toLowerCase()).filter(
    key=>Object.prototype.hasOwnProperty.call(selectors,key),
  ).map(key=>key+'='+selectors[key]);
  if(pairs.length)return pairs.slice(0,3).join(' ');
  return selectors.action?'action='+selectors.action:null;
}
function boundSuite(source:string,suite:SuiteResult|undefined){
  if(!suite||suite.engine!=='browser-preview'||suite.nativeFluentdVerified!==false||
    suite.stellarExportVerified!==false||!Array.isArray(suite.events))return null;
  const events=splitEvents(source,'single-line',MAX_EVENTS+1);
  if(!events.length||events.length!==suite.events.length||
    suite.counts.total!==events.length||
    events.some((event,i)=>event.raw!==suite.events[i]?.raw||event.line!==suite.events[i]?.line))
    return null;
  return suite.events;
}
function protectedOutput(event:SuiteResult['events'][number],draft:ParserDraft,
 mapping:ParserDraft['mappings'][number],group:ProtectedMapping['group']){
  const original=lookupFieldValue(event.fields,mapping.source);
  if(!original.found||original.value===null||original.value===undefined)return false;
  const normalized=group==='vendor_fields'
    ?event.normalized[draft.vendor] as Record<string,unknown>|undefined:event.normalized;
  return !!normalized&&typeof normalized==='object'&&!Array.isArray(normalized)&&
    lookupFieldValue(normalized,mapping.target).found;
}

/** Source-only event variants + source-bound successfully extracted field paths.
 * No inferred vendor names, no guessed timezones, no invented mappings and no
 * samples beyond the exact text manually supplied by the user.
 */
export function buildEventCoverageEvidence(
 source:string,draft?:ParserDraft,suite?:SuiteResult,
):EventCoverageEvidence{
  const events=splitEvents(source,'single-line',MAX_EVENTS+1);
  const counts=new Map<string,number>();
  let unclassified=0;
  for(const event of events){
    const selector=discoveredSelector(event.raw);
    if(!selector)unclassified++;
    else counts.set(selector,(counts.get(selector)??0)+1);
  }
  const sorted=[...counts].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]));
  const observedKinds:ObservedKind[]=sorted.slice(0,MAX_KINDS)
    .map(([selector,records])=>({selector,records}));
  const notes=[
    'Observed event-type diversity in the EXACT original source (source labels only; no manufacturer grammar assumed):',
    JSON.stringify({
      originalPhysicalRecords:events.length,
      observedKinds,
      additionalObservedKinds:Math.max(0,sorted.length-MAX_KINDS),
      recordsWithoutExplicitSelector:unclassified,
    }),
    'Different event types may have different field layouts. Cover EVERY distinct observed kind, including unspecified types, without overwriting existing extractions. A one-type sample is not proof of coverage for other product events.',
  ];
  if(sorted.length<2)notes.push(
    'Only '+sorted.length+' distinct explicit event selector(s) were observed. For a security product, include actual examples of its traffic, threat/IPS, malware/AV, web-filter, VPN, authentication and system events when those types exist. Do not fabricate missing examples or claim unsupported types are covered.',
  );
  const verified=boundSuite(source,suite);
  let protectedMappings=0;
  if(verified){
    const sourceFieldCounts=new Map<string,number>();
    for(const event of verified){
      if(!event.matched||!event.extracted)continue;
      for(const path of listSafeLeafPaths(event.fields,101).slice(0,101)){
        if(!safeLocalFieldPath(path))continue;
        sourceFieldCounts.set(path,(sourceFieldCounts.get(path)??0)+1);
      }
    }
    const sourceFields=[...sourceFieldCounts].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]))
      .slice(0,MAX_FIELDS).map(([sourcePath,records])=>({sourcePath,records}));
    if(sourceFields.length)notes.push(
      'Source field paths ALREADY extracted by local preview (observations, not guessed normalized meanings):',
      JSON.stringify({sourceFields,additionalPaths:Math.max(0,sourceFieldCounts.size-MAX_FIELDS)}),
      'Preserve the observed source fields if proposing a replacement grammar. Do not replace a previously extracted value with guessed or empty data.',
    );
    if(draft){
      const mappings:ProtectedMapping[]=[];
      for(const mapping of draft.mappings){
        if(!safeLocalFieldPath(mapping.source)||!safeLocalFieldPath(mapping.target))continue;
        const group=draft.guided?.groups[mapping.id]??'vendor_fields';
        if(!['top_fields','ns_fields','vendor_fields'].includes(group))continue;
        const observed=verified.filter(event=>protectedOutput(
          event,draft,mapping,group,
        )).length;
        if(!observed)continue;
        protectedMappings++;
        if(mappings.length>=MAX_MAPPINGS)continue;
        mappings.push({source:mapping.source,target:mapping.target,
          group,type:mapping.type,observedRecords:observed});
      }
      if(mappings.length)notes.push(
        'EXISTING successfully normalized mappings to preserve (same-source preview, not future holdout evidence):',
        JSON.stringify({mappings,otherVerifiedMappings:Math.max(0,protectedMappings-MAX_MAPPINGS)}),
        'Keep these source-to-target mappings and their types wherever the source fields are present. If a new grammar cannot retain an already correct field, return REVIEW_REQUIRED rather than dropping that field. Parser Studio will still test independent holdouts.',
      );
    }
  }
  return {text:notes.join('\n'),sourceRecords:events.length,
    observedKinds:sorted.length,unclassifiedRecords:unclassified,protectedMappings};
}
