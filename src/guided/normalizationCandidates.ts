import type {MappingRule,MappingWhen,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {convertValue} from '../parser';
import {meetsStellar7ValueConstraints} from '../stellar7ValueConstraints';
import semanticPolicy from '../../runtime/multipass/semantic-policy.v1.json';
import {sourceHasExcludedPortSegment,explicitPortSourceAlias} from './sourcePortPolicy';
export {sourceHasExcludedPortSegment,explicitPortSourceAlias} from './sourcePortPolicy';
import type {FieldGroup} from './contract';
import {findStellarMetadataField} from './stellarMetadataCatalog';

export interface NormalizationCandidate {
  source:string;
  target:string;
  type:MappingRule['type'];
  group:FieldGroup;
  confidence:'HIGH'|'REVIEW';
  method:'EXACT_DICTIONARY_NAME'|'DOCUMENTED_ALIAS';
  explanation:string;
  catalogVerified:true;
  catalogRelease:'7.0.xs';
  observed:number;
  compatibleObserved:number;
  total:number;
  replacesMappingId?:string;
  currentTarget?:string;
  safeForBulk:boolean;
  when?:MappingWhen;
  eligibleObserved:number;
  skippedForSemantics:number;
}

const ALIASES:Readonly<Record<string,string>>=semanticPolicy.normalizationAliases;

function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
}
function ignored(value:unknown):boolean{
  return value===null||value===undefined||['','N/A','-'].includes(String(value));
}

// Published 7.0 proto_name is a transport protocol, not a vendor application
// or service label. An unknown name is still reviewable, never auto-approved.
const DOCUMENTED_PROTO_NAMES=new Set(semanticPolicy.officialProtocolNames);
const TRANSPORT_NUMERIC=new Set<string>(
  semanticPolicy.transportPortProtocols.numeric.map(String));
const TRANSPORT_NAMES=new Set<string>(semanticPolicy.transportPortProtocols.names);
/** A protocol observation is not proof of a Layer 4 port unless it names an
 * independently reviewed carrier. Unknown/contradicting evidence is REVIEW. */
function unsupportedPortProtocolInEvent(
  fields:Record<string,unknown>,source:string,
):boolean{
  const prefix=source.includes('.')?source.slice(0,source.lastIndexOf('.')+1):'';
  const candidates=[prefix+'protocol-id',prefix+'protocol',prefix+'proto',
    prefix+'proto_name','protocol-id','protocol','proto','proto_name'];
  return candidates.some(name=>{
    const found=lookupFieldValue(fields,name);
    if(!found.found)return false;
    const value=String(found.value).trim().toLowerCase();
    return !(TRANSPORT_NUMERIC.has(value)||TRANSPORT_NAMES.has(value));
  });
}
/** Shared, versioned source-field contract. A declared port label has higher
 * identity evidence than abbreviated aliases (spt/sport etc). The field must
 * still pass Stellar's integer/range constraints and source ambiguity checks.
 * No vendor, product or sample-specific path is required.
 */
// A matching label is not enough: these vendor log fields have distinct
// meanings from Stellar's context-specific names or require unit conversion.
// Restrict the guard to records with FortiOS's recognizable field family so
// Windows/EDR payloads with independently supported semantics stay unaffected.
function fortiGateRecord(fields:Record<string,unknown>):boolean{
  return lookupFieldValue(fields,'logid').found&&
    (lookupFieldValue(fields,'vd').found||lookupFieldValue(fields,'srcintf').found)&&
    lookupFieldValue(fields,'type').found;
}
const FORTINET_FALSE_FRIENDS=new Set([
  'type','eventtype','event_type','direction','duration','hostname',
]);
// The official action field describes enforcement/response, not arbitrary
// event verbs such as a VPN negotiation, session close or admin login.
const SECURITY_DISPOSITIONS=new Set(semanticPolicy.securityDispositions);
function windowsAgentEvidence(fields:Record<string,unknown>):boolean{
  // The published top-level Stellar "type" is Windows-agent-specific.
  return ['provider_guid','record_number','log_name','event_data'].some(name=>
    lookupFieldValue(fields,name).found);
}
function suricataAlertEvidence(fields:Record<string,unknown>):boolean{
  const kind=lookupFieldValue(fields,'event_type');
  return kind.found&&String(kind.value).toLowerCase()==='alert'&&
    lookupFieldValue(fields,'alert.signature_id').found;
}
function incompatibleVendorMeaning(
  source:string,target:string,events:Record<string,unknown>[],
):boolean{
  const leaf=(source.split('.').at(-1)??source).toLowerCase();
  const lower=source.toLowerCase();
  // An exact dictionary field-name match cannot establish vendor semantics.
  // event_type is an ML-job event type in the 7.0 dictionary, not the
  // manufacturer's record family (Suricata alert, Okta session, etc.).
  if(target==='event_type')return true;
  if(target==='type'&&(!events.every(windowsAgentEvidence)||source!=='type'))return true;
  // Vendor traffic durations commonly use seconds or unspecified units.
  // Do not emit the official milliseconds field without explicit ms evidence.
  if(target==='duration'&&!['duration_ms','session_duration_ms'].includes(leaf))return true;
  if(target==='action'&&events.some(fields=>{
    const result=lookupFieldValue(fields,source);
    return result.found&&!ignored(result.value)&&
      !SECURITY_DISPOSITIONS.has(String(result.value).trim().toLowerCase());
  }))return true;
  // Suricata IDS priority severity (1-4) is not Stellar's 0-100 score.
  if(target==='severity'&&lower.endsWith('alert.severity')&&
    events.some(suricataAlertEvidence))return true;
  if(events.some(fortiGateRecord)&&FORTINET_FALSE_FRIENDS.has(leaf))return true;
  // RFC3164 PRI severity 0-7 is a Syslog facility code component, not
  // Stellar's 0-100 security severity score. Never silently relabel it.
  if(source.toLowerCase().endsWith('syslog.severity'))return true;
  // A reviewed PAN-OS positional CSV category is not the unrelated Stellar
  // Windows-agent 'type' field, even when a structural profile names it type.
  if(leaf==='type'&&source.toLowerCase().includes('generic.fields.')&&
    events.some(fields=>{
      const value=lookupFieldValue(fields,source);
      return value.found&&['TRAFFIC','THREAT','SYSTEM','CONFIG'].includes(String(value.value).toUpperCase());
    }))return true;
  // A zero-filled ICMP field on UDP or TCP is not evidence of ICMP semantics.
  if(target==='icmp_type'&&leaf==='icmp-type')return events.some(fields=>{
    if(!lookupFieldValue(fields,source).found)return false;
    const prefix=source.slice(0,source.length-leaf.length);
    const protocol=lookupFieldValue(fields,prefix+'protocol-id');
    return protocol.found&&!['1','58'].includes(String(protocol.value));
  });
  return false;
}
export function valueFitsMappingType(type:MappingRule['type'],value:unknown):boolean{
  if(ignored(value))return true;
  // Candidate confidence and whole-sample validation must use the same type
  // semantics as the actual browser/runtime normalization path. This keeps
  // IPv6 and explicit-timezone timestamps from diverging.
  return convertValue(value,type).error===undefined;
}
export function valueFitsNormalizationTarget(
  target:string,type:MappingRule['type'],value:unknown,
):boolean{
  if(ignored(value))return true;
  const converted=convertValue(value,type);
  return converted.error===undefined&&
    meetsStellar7ValueConstraints(target,value,converted.value);
}
function candidateForSource(source:string,events:Record<string,unknown>[],existing:MappingRule[],
 existingGroups:Record<string,FieldGroup>):NormalizationCandidate|null{
  const leaf=source.split('.').at(-1)??source;
  const exact=findStellarMetadataField(source);
  const leafExact=findStellarMetadataField(leaf);
  const target=exact?.mappable?source:
    leafExact?.mappable?leaf:
    ALIASES[source.toLowerCase()]??ALIASES[leaf.toLowerCase()];
  if(!target)return null;
  if((target==='srcport'||target==='dstport')&&sourceHasExcludedPortSegment(source))return null;
  if(incompatibleVendorMeaning(source,target,events))return null;
  const catalog=findStellarMetadataField(target);
  if(!catalog?.mappable||!catalog.mappingType||!catalog.group)return null;
  const current=existing.find(rule=>rule.source===source);
  const currentGroup=current?(existingGroups[current.id]??'vendor_fields'):undefined;
  const explicitPort=explicitPortSourceAlias(source,target);
  if(current&&current.target===target&&current.type===catalog.mappingType&&
     currentGroup===catalog.group&&!current.when)return null;
  if(existing.some(rule=>rule.id!==current?.id&&overlaps(rule.target,target)))return null;
  const values=events.map(fields=>lookupFieldValue(fields,source)).filter(result=>result.found);
  if(values.length===0)return null;
  const informativeValues=values.filter(result=>!ignored(result.value));
  const compatibleObserved=informativeValues.filter(result=>
    valueFitsNormalizationTarget(target,catalog.mappingType!,result.value)&&
    (target!=='proto_name'||DOCUMENTED_PROTO_NAMES.has(String(result.value).toLowerCase()))&&
    (target!=='proto'||(Number.isInteger(Number(result.value))&&
      Number(result.value)>=0&&Number(result.value)<=255))).length;
  // Protocol-gate abbreviated/ambiguous names; exact descriptive source
  // labels are an explicit source-identity contract, independent of vendor.
  const nonTransportPort=!explicitPort&&(target==='srcport'||target==='dstport')&&
    events.some(fields=>lookupFieldValue(fields,source).found&&
      unsupportedPortProtocolInEvent(fields,source));
  const method:NormalizationCandidate['method']=target===source?'EXACT_DICTIONARY_NAME':'DOCUMENTED_ALIAS';
  // All event samples must contain this source and at least one usable value.
  // A sparse heterogeneous sample or placeholders are not sufficient evidence
  // for a bulk-approved official field mapping.
  const informative=informativeValues.length;
  const high=compatibleObserved===informative&&values.length===events.length&&
    informative>0&&!nonTransportPort;
  // Auto-generated provenance is explicit; field names and IDs cannot prove
  // that a user has not edited a persisted mapping.
  const replaceIsGenerated=current?.authoring?.version===1&&
    current.authoring.origin==='AUTO';
  return {
    source,target,type:catalog.mappingType,group:catalog.group,
    confidence:high?'HIGH':'REVIEW',method,
    explanation:high&&explicitPort
      ?'The source explicitly names a port. Its validated integer value maps to the published Stellar field; non-TCP/UDP events may carry vendor-specific numeric identifiers rather than L4 transport ports.'
      :high
      ?(method==='EXACT_DICTIONARY_NAME'
        ?'Source name matches the official Stellar metadata field and observed values match its documented type.'
        :'Reviewed source alias maps to an official Stellar metadata field and observed values match its documented type.')
      :nonTransportPort
        ?'An abbreviated port field with unknown or non-transport protocol context needs review before mapping to an L4 port.'
        :values.length!==events.length
        ?'The field is missing from some events; review its event-family scope before applying an official mapping.'
        :informative===0
          ?'The source contains no informative values; a matching name alone is not enough to approve an official mapping.'
          :'The field-name match is plausible, but at least one observed value is incompatible with the documented Stellar field meaning or value type.',
    catalogVerified:true,catalogRelease:'7.0.xs',observed:values.length,
    compatibleObserved,total:events.length,
    eligibleObserved:values.length,skippedForSemantics:0,
    ...(current?{replacesMappingId:current.id,currentTarget:current.target}:{}),
    safeForBulk:high&&(!current||replaceIsGenerated),
  };
}
/** Limit expensive per-event semantic checks without silently sampling input order.
 * Catalog/alias eligibility is a cheap name-only prefilter. If more than the
 * bounded budget qualify, do not infer ANY official field from an incomplete
 * competition set; the UI shows a blocking review warning instead. */
export const MAX_OFFICIAL_CANDIDATE_SCAN=1024;
export function normalizationCandidateScanStatus(suite:SuiteResult|undefined):{
  eligiblePaths:number;limit:number;exceeded:boolean;paths:string[];
  sourceScanTruncated:boolean;
}{
  const sources=new Set<string>();
  let sourceScanTruncated=false;
  // Authoring is separately limited to 100 fields per event, but official
  // mapping competition must inspect ALL safe paths within its own 1024-path
  // budget. A large valid PAN-OS CSV can exceed 100 raw fields; refusing it
  // wholesale would erase independently qualified official source mappings.
  // The 1025th source path is a fail-closed overflow sentinel.
  for(const event of suite?.events??[]){
    const paths=listSafeLeafPaths(event.fields,1025);
    if(paths.length>MAX_OFFICIAL_CANDIDATE_SCAN){
      sourceScanTruncated=true;
      continue;
    }
    for(const path of paths)sources.add(path);
  }
  const eligible=[...sources].filter(source=>{
    const leaf=source.split('.').at(-1)??source;
    return Boolean(findStellarMetadataField(source)?.mappable||
      findStellarMetadataField(leaf)?.mappable||
      ALIASES[source.toLowerCase()]||ALIASES[leaf.toLowerCase()]);
  });
  // Preserve the established single-event suggestion order for beginner UX.
  // With multiple event families, deterministic lexical order makes reversed
  // event ordering produce the exact same REVIEW candidate list.
  if((suite?.events.length??0)>1)eligible.sort();
  const exceeded=sourceScanTruncated||eligible.length>MAX_OFFICIAL_CANDIDATE_SCAN;
  return {eligiblePaths:eligible.length,limit:MAX_OFFICIAL_CANDIDATE_SCAN,
    exceeded,sourceScanTruncated,paths:exceeded?[]:eligible};
}
export function suggestNormalizationCandidatesFromSuite(
  suite:SuiteResult|undefined,existing:MappingRule[],existingGroups:Record<string,FieldGroup>={},
  options:{skipAmbiguousTargets?:boolean}={},
):NormalizationCandidate[]{
  if(!suite?.events.length)return [];
  const fields=suite.events.map(event=>event.fields);
  const scan=normalizationCandidateScanStatus(suite);
  // An incomplete candidate set could hide a competing official destination.
  // Fail closed instead of marking the first 100 paths as complete.
  if(scan.exceeded)return [];
  const proposed:NormalizationCandidate[]=[];
  const candidatesByTarget=new Map<string,NormalizationCandidate[]>();
  for(const source of scan.paths){
    const candidate=candidateForSource(source,fields,existing,existingGroups);
    if(!candidate)continue;
    candidatesByTarget.set(candidate.target,[...(candidatesByTarget.get(candidate.target)??[]),candidate]);
    proposed.push(candidate);
  }
  // Competing sources are ambiguous only if more than one has actual values
  // compatible with the official target. A standalone Syslog HH:MM:SS is not
  // a competing timestamp to an independently qualified timezone date/time.
  const ambiguousTargets=new Set([...candidatesByTarget.entries()]
    .filter(([,candidates])=>candidates.filter(candidate=>candidate.compatibleObserved>0).length>1)
    .map(([target])=>target));
  // Never silently let insertion order select an official destination when
  // two distinct source paths are plausible. Keep both visible for human
  // review, but neither can be bulk-applied without resolving the conflict.
  const reviewed=proposed.map(candidate=>ambiguousTargets.has(candidate.target)
    ?{...candidate,confidence:'REVIEW' as const,safeForBulk:false,
      explanation:'The multiple source fields map to the same official Stellar destination; review the source meaning and select one manually.'}
    :candidate);
  return options.skipAmbiguousTargets
    ?reviewed.filter(candidate=>!ambiguousTargets.has(candidate.target)):reviewed;
}

/** Backward-compatible selected-event helper used by the Review Fields summary. */
export function suggestNormalizationCandidates(
  fields:Record<string,unknown>,existing:MappingRule[],
):NormalizationCandidate[]{
  const suite={events:[{fields}]} as unknown as SuiteResult;
  return suggestNormalizationCandidatesFromSuite(suite,existing);
}
