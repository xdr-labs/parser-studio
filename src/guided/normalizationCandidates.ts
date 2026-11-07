import type {MappingRule,MappingWhen,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {convertValue} from '../parser';
import {meetsStellar7ValueConstraints} from '../stellar7ValueConstraints';
import semanticPolicy from '../../runtime/multipass/semantic-policy.v1.json';
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

const ALIASES:Record<string,string>={
  // Common vendor/CEF/LEEF source address spellings. Value/type evidence must
  // still agree with the official Stellar destination before HIGH confidence.
  src:'srcip',src_ip:'srcip',source_ip:'srcip',sourceip:'srcip',
  sourceipaddress:'srcip',sourceaddress:'srcip',srcaddress:'srcip',
  'source.ip':'srcip','source.address':'srcip','source.ipaddress':'srcip',
  // RFC5424 Structured Data and Juniper RT_FLOW use literal hyphenated keys.
  // Preserve their complete source paths; only normalize the destination.
  'source-address':'srcip',
  client_ip:'srcip',clientip:'srcip','client.ip':'srcip','client.ipaddress':'srcip',
  'httprequest.clientip':'srcip',
  'body.src':'srcip','body.src_ip':'srcip','body.source_ip':'srcip',
  dst:'dstip',dst_ip:'dstip',destination_ip:'dstip',destinationip:'dstip',
  dest_ip:'dstip',destip:'dstip',destinationaddress:'dstip',dstaddress:'dstip',
  'destination.ip':'dstip','destination.address':'dstip','destination.ipaddress':'dstip',
  'destination-address':'dstip',
  server_ip:'dstip','server.ip':'dstip',
  'body.dst':'dstip','body.dst_ip':'dstip','body.destination_ip':'dstip',
  spt:'srcport',sport:'srcport',src_port:'srcport',source_port:'srcport',sourceport:'srcport',
  srcport:'srcport','source.port':'srcport',client_port:'srcport',
  'source-port':'srcport',
  'body.spt':'srcport','body.srcport':'srcport','body.src_port':'srcport',
  dpt:'dstport',dport:'dstport',dst_port:'dstport',destination_port:'dstport',destinationport:'dstport',
  dest_port:'dstport',destport:'dstport',dstport:'dstport',
  'destination.port':'dstport',server_port:'dstport',
  'destination-port':'dstport',
  'body.dpt':'dstport','body.dstport':'dstport','body.dst_port':'dstport',
  act:'action',event_action:'action',eventaction:'action','event.action':'action',
  'body.act':'action','body.action':'action',
  event_time:'timestamp',eventtime:'timestamp','event.time':'timestamp','event.timestamp':'timestamp',
  '@timestamp':'timestamp',syslog_timestamp:'timestamp',date_time:'timestamp',time:'timestamp',
  host_name:'hostname',hostname:'hostname',host:'hostname','host.name':'hostname',device_name:'hostname',
  devicename:'hostname','device.hostname':'hostname',syslog_hostname:'hostname',unit_hostname:'hostname',
  ip_client:'srcip',protocol:'proto_name',
  'protocol-id':'proto','policy-name':'rule.name','icmp-type':'icmp_type',
  policyid:'fw_policy_id',
  // The explicit unit suffix is required: Stellar duration is milliseconds.
  duration_ms:'duration',session_duration_ms:'duration',
  // request_status is not an action alias: an HTTP status code and a security
  // allow/deny action have different semantics even if both are strings.
  uri:'url',
  localip:'hostip',username:'username',processname:'process_name',
  commandline:'command',parentprocess:'parent_proc_name',
  eventtype:'event_type',
};

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
// Juniper SD RT_FLOW source-port is not unconditionally an L4 port.
// Its ICMP records contain vendor protocol identifiers in the same slot.
// Bound the official map to independently observed TCP/UDP protocol numbers.
function juniperTransportWhen(
  source:string,events:Record<string,unknown>[],
):MappingWhen|undefined{
  const prefix='syslog_sd.element_1.params.';
  if(source!==prefix+'source-port'&&source!==prefix+'destination-port')return;
  if(!events.every(fields=>{
    const sd=lookupFieldValue(fields,'syslog_sd.element_1.sd_id');
    const app=lookupFieldValue(fields,'syslog_appname');
    const port=lookupFieldValue(fields,source);
    const proto=lookupFieldValue(fields,prefix+'protocol-id');
    return sd.found&&String(sd.value).startsWith('junos@')&&
      app.found&&app.value==='RT_FLOW'&&
      (!port.found||(proto.found&&/^\d{1,3}$/.test(String(proto.value))&&
        Number(proto.value)<=255));
  }))return;
  return {sourcePath:prefix+'protocol-id',operator:'in',values:['6','17']};
}
function juniperPortWithMissingProtocolContext(
  source:string,events:Record<string,unknown>[],
):boolean{
  const prefix='syslog_sd.element_1.params.';
  if(![prefix+'source-port',prefix+'destination-port'].includes(source))return false;
  return events.some(fields=>{
    const sd=lookupFieldValue(fields,'syslog_sd.element_1.sd_id');
    const app=lookupFieldValue(fields,'syslog_appname');
    const port=lookupFieldValue(fields,source);
    return sd.found&&String(sd.value).startsWith('junos@')&&
      app.found&&app.value==='RT_FLOW'&&port.found;
  });
}
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
  if(incompatibleVendorMeaning(source,target,events))return null;
  const catalog=findStellarMetadataField(target);
  if(!catalog?.mappable||!catalog.mappingType||!catalog.group)return null;
  const current=existing.find(rule=>rule.source===source);
  const currentGroup=current?(existingGroups[current.id]??'vendor_fields'):undefined;
  const when=(target==='srcport'||target==='dstport')
    ?juniperTransportWhen(source,events):undefined;
  if(current&&current.target===target&&current.type===catalog.mappingType&&
     currentGroup===catalog.group&&JSON.stringify(current.when)===JSON.stringify(when))return null;
  if(existing.some(rule=>rule.id!==current?.id&&overlaps(rule.target,target)))return null;
  const values=events.map(fields=>lookupFieldValue(fields,source)).filter(result=>result.found);
  if(values.length===0)return null;
  const applicable=when
    ?events.filter(fields=>{
      const p=lookupFieldValue(fields,when.sourcePath);
      return p.found&&when.values.includes(String(p.value));
    }).map(fields=>lookupFieldValue(fields,source)).filter(result=>result.found)
    :values;
  const informativeValues=applicable.filter(result=>!ignored(result.value));
  const compatibleObserved=informativeValues.filter(result=>
    valueFitsNormalizationTarget(target,catalog.mappingType!,result.value)&&
    (target!=='proto_name'||DOCUMENTED_PROTO_NAMES.has(String(result.value).toLowerCase()))&&
    (target!=='proto'||(Number.isInteger(Number(result.value))&&
      Number(result.value)>=0&&Number(result.value)<=255))).length;
  // ICMP/IGMP field names sometimes carry identifiers rather than Layer 4
  // ports. Preserve them as vendor fields unless a human reviews the meaning.
  const nonTransportPort=!when&&(target==='srcport'||target==='dstport')&&
    events.some(fields=>lookupFieldValue(fields,source).found&&
      unsupportedPortProtocolInEvent(fields,source));
  const method:NormalizationCandidate['method']=target===source?'EXACT_DICTIONARY_NAME':'DOCUMENTED_ALIAS';
  // All event samples must contain this source and at least one usable value.
  // A sparse heterogeneous sample or placeholders are not sufficient evidence
  // for a bulk-approved official field mapping.
  const informative=informativeValues.length;
  const missingJuniperContext=!when&&(target==='srcport'||target==='dstport')&&
    juniperPortWithMissingProtocolContext(source,events);
  const high=compatibleObserved===informative&&values.length===events.length&&
    informative>0&&!nonTransportPort&&!missingJuniperContext;
  const defaultGenerated=new Map([
    ['source-ip','custom.source_ip'],['target-port','custom.destination_port'],['action','custom.action'],
  ]);
  const replaceIsGenerated=Boolean(current&&(
    (current.id.startsWith('auto-')&&currentGroup==='vendor_fields')||
    (current.target.startsWith('custom.')&&defaultGenerated.get(current.id)===current.target)
  ));
  return {
    source,target,type:catalog.mappingType,group:catalog.group,
    confidence:high?'HIGH':'REVIEW',method,
    explanation:when&&informative>0&&high
      ?'Juniper RT_FLOW uses this source field for multiple protocols. Emit the Stellar L4 port only for TCP (6) or UDP (17); preserve the original vendor value for ICMP/IGMP and unknown protocols.'
      :when&&informative===0
        ?'The current Juniper ICMP/IGMP sample has no eligible TCP/UDP port value; preserve the vendor field until a transport event can be reviewed.'
      :high
      ?(method==='EXACT_DICTIONARY_NAME'
        ?'Source name matches the official Stellar metadata field and observed values match its documented type.'
        :'Reviewed source alias maps to an official Stellar metadata field and observed values match its documented type.')
      :missingJuniperContext
        ?'Juniper RT_FLOW needs a valid protocol ID in every port-bearing event before official Layer 4 port mapping can be considered.'
      :nonTransportPort
        ?'An unknown or non-transport IP protocol does not establish Layer 4 port semantics; review vendor values before mapping to srcport or dstport.'
        :values.length!==events.length
        ?'The field is missing from some events; review its event-family scope before applying an official mapping.'
        :informative===0
          ?'The source contains no informative values; a matching name alone is not enough to approve an official mapping.'
          :'The field-name match is plausible, but at least one observed value is incompatible with the documented Stellar field meaning or value type.',
    catalogVerified:true,catalogRelease:'7.0.xs',observed:values.length,
    compatibleObserved,total:events.length,
    ...(when?{when}:{}),eligibleObserved:applicable.length,
    skippedForSemantics:values.length-applicable.length,
    ...(current?{replacesMappingId:current.id,currentTarget:current.target}:{}),
    safeForBulk:high&&(!current||replaceIsGenerated),
  };
}
export function suggestNormalizationCandidatesFromSuite(
  suite:SuiteResult|undefined,existing:MappingRule[],existingGroups:Record<string,FieldGroup>={},
  options:{skipAmbiguousTargets?:boolean}={},
):NormalizationCandidate[]{
  if(!suite?.events.length)return [];
  const fields=suite.events.map(event=>event.fields);
  const sources=new Set<string>();
  for(const event of fields)for(const path of listSafeLeafPaths(event))sources.add(path);
  const proposed:NormalizationCandidate[]=[];
  const candidatesByTarget=new Map<string,NormalizationCandidate[]>();
  for(const source of [...sources].slice(0,100)){
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
