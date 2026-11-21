import type {MappingRule,MappingWhen,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {convertValue} from '../parser';
import {canonicalIgnoreSourceValue} from '../../backend/src/canonical-operator-contract';
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
const WHITESPACE_FREE_TARGETS=new Set(['srcport','dstport','srcip','dstip']);
/** Official fields a sparse source may be approved for when the source is named exactly like the field. */
const SPARSE_SAFE_TARGETS=new Set(['srcip','dstip','srcport','dstport','proto','proto_name','url']);
/** A sparse source is approved only where the name stands for the record itself: at the root, or in the
 * container the READER of the event puts the record's own pairs in. Which containers those are follows from
 * the reading (the effective format of the events that carry the source), never from the text of the path: in
 * a JSON log `fields.srcip`, `body.srcip` or `xlate.srcip` is an object of the log and names another endpoint. */
const GENERIC_STRUCTURAL_CONTAINER=/^(?:generic\.(?:kv|fields)|watchguard\.kv|junos_sd|body)\.[^.]+$/u;
const SYSLOG_BODY_CONTAINER=/^body\.[^.]+$/u;
function recordLevelSource(source:string,formats:readonly (string|undefined)[]):boolean{
  if(!source.includes('.'))return true;
  return formats.length>0&&formats.every(format=>
    format==='generic_structural'?GENERIC_STRUCTURAL_CONTAINER.test(source):
    format==='syslog_rfc3164'||format==='syslog_rfc5424'?SYSLOG_BODY_CONTAINER.test(source):false);
}
const URL_SHAPED=/^(?:[a-z][a-z0-9+.-]*:\/\/\S+|\/\S*)$/iu;
type Looked={found:true;value:unknown}|{found:false};
function sparseSafeSource(source:string,target:string,values:readonly Looked[],
  formats:readonly (string|undefined)[]):boolean{
  if(!recordLevelSource(source,formats)||sourceHasExcludedPortSegment(source))return false;
  // The other sparse-safe fields are checked by the type of the field; a URL has no such check.
  return target!=='url'||values.every(result=>result.found&&typeof result.value==='string'&&
    URL_SHAPED.test(result.value.trim()));
}
/** Field names under which a record states its IP protocol. `transport` is not one of them: FortiGate writes
 * the translated source port under that name. */
const PROTOCOL_EVIDENCE_NAMES=['protocol-id','protocol_id','protocol','proto','proto_name','protocol_name',
  'ipproto','ip_proto','l4proto'];
/** Aliases whose documented meaning depends on the protocol: Zeek writes the ICMP type and code in
 * id.orig_p and id.resp_p. They are ports only beside a TCP or UDP protocol. */
const PROTOCOL_DEPENDENT_PORT_ALIASES=new Set(['id.orig_p','id.resp_p']);
/** The source key behind a Generic Structural `atoms.<key>_001` first piece. */
function firstAtomKeyOf(source:string):string|undefined{
  return /^(?:.+\.)?atoms\.([A-Za-z0-9_]+)_001$/.exec(source)?.[1];
}

function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
}
/** A value the run time does not map and does not count as an error: absent, a blank-only string
 * (canonicalIgnoreSourceValue), or a placeholder. The review of a sample must agree with the run time. */
export function ignored(value:unknown):boolean{
  return canonicalIgnoreSourceValue(value,[])||['','N/A','-'].includes(String(value));
}

// Published 7.0 proto_name is a transport protocol, not a vendor application
// or service label. An unknown name is still reviewable, never auto-approved.
const DOCUMENTED_PROTO_NAMES=new Set(semanticPolicy.officialProtocolNames);
const TRANSPORT_NUMERIC=new Set<string>(
  semanticPolicy.transportPortProtocols.numeric.map(String));
const TRANSPORT_NAMES=new Set<string>(semanticPolicy.transportPortProtocols.names);
/** Where the protocol that qualifies `source` is recorded. An atom such as
 * `generic.atoms.dport_001` is a slice of `generic.kv.dport`, so the protocol
 * lives beside the KV carrier, not beside the atom. */
function protocolContextPrefixes(source:string):string[]{
  const prefix=source.includes('.')?source.slice(0,source.lastIndexOf('.')+1):'';
  if(firstAtomKeyOf(source)===undefined)return [prefix];
  return [prefix,source.slice(0,source.lastIndexOf('atoms.'))+'kv.'];
}
function objectAt(fields:Record<string,unknown>,path:string):Record<string,unknown>|null{
  if(!path)return fields;
  const found=lookupFieldValue(fields,path);
  return found.found&&found.value!==null&&typeof found.value==='object'&&!Array.isArray(found.value)
    ?found.value as Record<string,unknown>:null;
}
/** What the record says about its IP protocol beside `source`: the values of the protocol fields in the object
 * that holds the source (for an atom also in the key=value carrier beside it). Field names are compared without
 * regard to case, as the aliases are (`Protocol=ICMP` beside `SrcPort`). `withRoot` adds the root of the event;
 * a source whose path names no object (a literal dotted key such as Zeek's id.orig_p) is at the root. */
function protocolValuesBeside(fields:Record<string,unknown>,source:string,withRoot:boolean):string[]{
  const containers=new Set<Record<string,unknown>>();
  for(const prefix of protocolContextPrefixes(source)){
    const container=objectAt(fields,prefix.endsWith('.')?prefix.slice(0,-1):prefix);
    if(container)containers.add(container);
  }
  if(withRoot||containers.size===0)containers.add(fields);
  const values:string[]=[];
  for(const container of containers)for(const key of Object.keys(container)){
    if(!PROTOCOL_EVIDENCE_NAMES.includes(key.toLowerCase()))continue;
    const value=container[key];
    if(value===null||value===undefined||typeof value==='object')continue;
    values.push(String(value).trim().toLowerCase());
  }
  return values;
}
const isTransport=(value:string):boolean=>TRANSPORT_NUMERIC.has(value)||TRANSPORT_NAMES.has(value);
/** A protocol observation is not proof of a Layer 4 port unless it names an
 * independently reviewed carrier. Unknown/contradicting evidence is REVIEW. */
function unsupportedPortProtocolInEvent(
  fields:Record<string,unknown>,source:string,
):boolean{
  return protocolValuesBeside(fields,source,true).some(value=>!isTransport(value));
}
/** The record itself says that its ports are TCP or UDP ports: in the object that holds the port, not at the
 * root of an event whose port lives in a nested family. */
function transportEvidenceInEvent(fields:Record<string,unknown>,source:string):boolean{
  return protocolValuesBeside(fields,source,false).some(isTransport);
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
/** The containers around a source field as path prefixes, innermost first, the root ('') last.
 * One vendor record is read at the root by the KV and JSON formats and inside a container by others
 * (generic.kv.*, body.*, a Syslog-wrapped JSON body). What a record is does not depend on which reading produced
 * it, so the evidence that names the record is looked for in each container around the field - all of it in the
 * same container, never pieced together from different levels. Looking at the root only left the guards below
 * silent for the same record behind a PRI: a FortiGate web-filter line read by Generic Structural had its
 * requested web host mapped to Stellar hostname. */
function recordPrefixes(source:string):string[]{
  const prefixes:string[]=[];
  for(let end=source.lastIndexOf('.');end>0;end=source.lastIndexOf('.',end-1))prefixes.push(source.slice(0,end+1));
  prefixes.push('');
  return prefixes;
}
function fortiGateRecord(fields:Record<string,unknown>,source:string):boolean{
  return recordPrefixes(source).some(prefix=>
    lookupFieldValue(fields,prefix+'logid').found&&
    (lookupFieldValue(fields,prefix+'vd').found||lookupFieldValue(fields,prefix+'srcintf').found)&&
    lookupFieldValue(fields,prefix+'type').found);
}
const FORTINET_FALSE_FRIENDS=new Set([
  'type','eventtype','event_type','direction','duration','hostname',
]);
/** One rule for every consumer (automatic candidates and reviewed ChatGPT proposals): a FortiOS field whose name
 * equals a Stellar field of another meaning or unit. */
export function fortiGateFalseFriend(source:string,events:readonly Record<string,unknown>[]):boolean{
  const leaf=source.slice(source.lastIndexOf('.')+1).toLowerCase();
  return FORTINET_FALSE_FRIENDS.has(leaf)&&events.some(fields=>fortiGateRecord(fields,source));
}
// The official action field describes enforcement/response, not arbitrary
// event verbs such as a VPN negotiation, session close or admin login.
const SECURITY_DISPOSITIONS=new Set(semanticPolicy.securityDispositions);
function windowsAgentEvidence(fields:Record<string,unknown>):boolean{
  // The published top-level Stellar "type" is Windows-agent-specific.
  return ['provider_guid','record_number','log_name','event_data'].some(name=>
    lookupFieldValue(fields,name).found);
}
function suricataAlertEvidence(fields:Record<string,unknown>,source:string):boolean{
  return recordPrefixes(source).some(prefix=>{
    const kind=lookupFieldValue(fields,prefix+'event_type');
    return kind.found&&String(kind.value).toLowerCase()==='alert'&&
      lookupFieldValue(fields,prefix+'alert.signature_id').found;
  });
}
const HTTP_METHOD_NAMES=['method','request_method','http_method'];
const HTTP_REQUEST_NAMES=['uri','url','request_uri','user_agent','useragent','status_code','referrer','referer'];
/** The object that holds `source` is an HTTP request record: it names the method and the requested resource,
 * the agent or the response status. Names are compared without regard to case. */
function httpRequestRecord(fields:Record<string,unknown>,source:string):boolean{
  const parent=source.includes('.')?source.slice(0,source.lastIndexOf('.')):'';
  const container=objectAt(fields,parent)??fields;
  const names=Object.keys(container).map(name=>name.toLowerCase());
  return HTTP_METHOD_NAMES.some(name=>names.includes(name))&&HTTP_REQUEST_NAMES.some(name=>names.includes(name));
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
    events.some(fields=>suricataAlertEvidence(fields,source)))return true;
  if(fortiGateFalseFriend(source,events))return true;
  // CEF names spt the source port. Imperva Cloud WAF (Incapsula) writes the client port as cpt and uses spt for the
  // SERVER port (its log file structure reference), with src still the client address: spt mapped to srcport would
  // pair the client address with the server port. A record that carries cpt beside spt follows that usage.
  if(target==='srcport'&&leaf==='spt'&&events.some(fields=>
    lookupFieldValue(fields,source).found&&
    lookupFieldValue(fields,source.slice(0,source.lastIndexOf('.')+1)+'cpt').found))return true;
  // An HTTP request record names the requested host `host` (the Host header: Zeek http.log, web access logs).
  // That is the site the client asked for, not the host the record is about or the one that wrote it.
  if(target==='hostname'&&leaf==='host'&&events.some(fields=>
    lookupFieldValue(fields,source).found&&httpRequestRecord(fields,source)))return true;
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
  // The Junos structured-data reader of the Generic Structural route spells the same two names with
  // underscores (icmp_type beside protocol_id). A field that is called icmp_type on its own is not this record.
  if(target==='icmp_type'&&(leaf==='icmp-type'||leaf==='icmp_type'))return events.some(fields=>{
    if(!lookupFieldValue(fields,source).found)return false;
    const prefix=source.slice(0,source.length-leaf.length);
    const protocol=lookupFieldValue(fields,prefix+(leaf==='icmp-type'?'protocol-id':'protocol_id'));
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
 existingGroups:Record<string,FieldGroup>,formats:readonly (string|undefined)[]=[]):NormalizationCandidate|null{
  // Generic Structural space_kv lets an unquoted value run up to the next key,
  // so `dport=53 pattern: allow all` stores the whole text under kv.dport and
  // its whitespace-separated pieces under atoms.dport_001... A port or IP never
  // contains whitespace, hence the first piece is the value and the rest is
  // trailing free text. Other targets (timestamps, sizes, messages) can span
  // tokens and therefore never accept an atom.
  const atomKey=firstAtomKeyOf(source);
  const leaf=atomKey===undefined?source.split('.').at(-1)??source:atomKey;
  const exact=findStellarMetadataField(source);
  const leafExact=findStellarMetadataField(leaf);
  let target=exact?.mappable?source:
    leafExact?.mappable?leaf:
    ALIASES[source.toLowerCase()]??ALIASES[leaf.toLowerCase()];
  // Stellar's proto is the IP protocol number and proto_name its name. A source field called proto whose
  // usable values are all documented protocol names (tcp, udp, icmp, igmp) holds the name, not the number.
  if(target==='proto'){
    const observed=events.map(fields=>lookupFieldValue(fields,source))
      .filter(result=>result.found&&!ignored(result.value));
    if(observed.length>0&&observed.every(result=>result.found&&typeof result.value==='string'&&
      DOCUMENTED_PROTO_NAMES.has(result.value.trim().toLowerCase())))target='proto_name';
  }
  if(atomKey!==undefined&&target&&!WHITESPACE_FREE_TARGETS.has(target))return null;
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
  // A source needs at least one usable value, and every usable value must fit the target.
  // It must also be present in every event: in a sample of several record families a name may belong to one
  // family only, so a sparse source stays a "check first" proposal.
  // The exception is a network endpoint or URL field (SPARSE_SAFE_TARGETS) whose source carries the official
  // name itself at the level of the record: the name leaves no other reading, and the value is checked by its
  // form (address, port range with TCP or UDP named by the record, protocol, URL shape). Mixed samples
  // (traffic, web filter and system records of one device) hold such a field in some events only; the mapping
  // writes nothing for an event without it. Other official names (severity, type, icmp_type ...), aliases and
  // explicit port labels keep the full-coverage rule.
  const informative=informativeValues.length;
  const carrierFormats=events.flatMap((fields,index)=>lookupFieldValue(fields,source).found?[formats[index]]:[]);
  const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&leaf.toLowerCase()===target&&sparseSafeSource(source,target,informativeValues,carrierFormats);
  // Unknown protocol evidence never authorizes an official port. A port that only some record families carry,
  // or an alias whose meaning depends on the protocol, needs the record itself to name TCP or UDP in every
  // event that has the port: an ICMP record of another family may name its protocol differently, or not at all.
  // An event that carries the port key with a placeholder (`-`, empty) does not make the port "present in every event".
  const needsTransportEvidence=(target==='srcport'||target==='dstport')&&
    (informativeValues.length!==events.length||PROTOCOL_DEPENDENT_PORT_ALIASES.has(source.toLowerCase()));
  const lacksTransportEvidence=needsTransportEvidence&&events.some(fields=>{
    const value=lookupFieldValue(fields,source);
    return value.found&&!ignored(value.value)&&!transportEvidenceInEvent(fields,source);
  });
  const high=compatibleObserved===informative&&(values.length===events.length||namedAsTarget)&&
    informative>0&&!nonTransportPort&&!lacksTransportEvidence;
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
    const atomKey=firstAtomKeyOf(source);
    const leaf=atomKey===undefined?source.split('.').at(-1)??source:atomKey;
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
    const candidate=candidateForSource(source,fields,existing,existingGroups,suite.events.map(event=>event.effectiveFormat));
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
