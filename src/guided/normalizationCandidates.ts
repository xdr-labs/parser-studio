import type {MappingRule,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {convertValue} from '../parser';
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
}

const ALIASES:Record<string,string>={
  // Common vendor/CEF/LEEF source address spellings. Value/type evidence must
  // still agree with the official Stellar destination before HIGH confidence.
  src:'srcip',src_ip:'srcip',source_ip:'srcip',sourceip:'srcip',
  sourceipaddress:'srcip',sourceaddress:'srcip',srcaddress:'srcip',
  'source.ip':'srcip','source.address':'srcip','source.ipaddress':'srcip',
  client_ip:'srcip',clientip:'srcip','client.ip':'srcip','client.ipaddress':'srcip',
  'httprequest.clientip':'srcip',
  'body.src':'srcip','body.src_ip':'srcip','body.source_ip':'srcip',
  dst:'dstip',dst_ip:'dstip',destination_ip:'dstip',destinationip:'dstip',
  dest_ip:'dstip',destip:'dstip',destinationaddress:'dstip',dstaddress:'dstip',
  'destination.ip':'dstip','destination.address':'dstip','destination.ipaddress':'dstip',
  server_ip:'dstip','server.ip':'dstip',
  'body.dst':'dstip','body.dst_ip':'dstip','body.destination_ip':'dstip',
  spt:'srcport',sport:'srcport',src_port:'srcport',source_port:'srcport',sourceport:'srcport',
  srcport:'srcport','source.port':'srcport',client_port:'srcport',
  'body.spt':'srcport','body.srcport':'srcport','body.src_port':'srcport',
  dpt:'dstport',dport:'dstport',dst_port:'dstport',destination_port:'dstport',destinationport:'dstport',
  dest_port:'dstport',destport:'dstport',dstport:'dstport',
  'destination.port':'dstport',server_port:'dstport',
  'body.dpt':'dstport','body.dstport':'dstport','body.dst_port':'dstport',
  act:'action',event_action:'action',eventaction:'action','event.action':'action',
  'body.act':'action','body.action':'action',
  event_time:'timestamp',eventtime:'timestamp','event.time':'timestamp','event.timestamp':'timestamp',
  '@timestamp':'timestamp',syslog_timestamp:'timestamp',date_time:'timestamp',time:'timestamp',
  host_name:'hostname',hostname:'hostname',host:'hostname','host.name':'hostname',device_name:'hostname',
  devicename:'hostname','device.hostname':'hostname',syslog_hostname:'hostname',unit_hostname:'hostname',
  ip_client:'srcip',protocol:'proto_name',
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
  const hashKind=/(?:^|\.)(md5|sha1|sha256)$/.exec(target)?.[1];
  if(hashKind){
    const widths:Record<string,number>={md5:32,sha1:40,sha256:64};
    return typeof value==='string' && new RegExp('^[0-9a-fA-F]{'+widths[hashKind]+'}$').test(value);
  }
  // An HTTP numeric result and a security action are not equivalent.
  if(target==='action'&&typeof value!=='string')return false;
  // Stellar documents L4 ports as integer fields, but their semantic range
  // remains 0..65535. Keep the documented target type while applying the
  // stricter field constraint before a HIGH-confidence mapping is offered.
  if(target==='srcport'||target==='dstport')
    return convertValue(value,'port').error===undefined;
  if(target==='severity'){
    const converted=convertValue(value,'integer');
    return converted.error===undefined&&typeof converted.value==='number'&&
      converted.value>=0&&converted.value<=100;
  }
  return valueFitsMappingType(type,value);
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
  const catalog=findStellarMetadataField(target);
  if(!catalog?.mappable||!catalog.mappingType||!catalog.group)return null;
  const current=existing.find(rule=>rule.source===source);
  const currentGroup=current?(existingGroups[current.id]??'vendor_fields'):undefined;
  if(current&&current.target===target&&current.type===catalog.mappingType&&
     currentGroup===catalog.group)return null;
  if(existing.some(rule=>rule.id!==current?.id&&overlaps(rule.target,target)))return null;
  const values=events.map(fields=>lookupFieldValue(fields,source)).filter(result=>result.found);
  if(values.length===0)return null;
  const informativeValues=values.filter(result=>!ignored(result.value));
  const compatibleObserved=informativeValues.filter(result=>
    valueFitsNormalizationTarget(target,catalog.mappingType!,result.value)).length;
  const method:NormalizationCandidate['method']=target===source?'EXACT_DICTIONARY_NAME':'DOCUMENTED_ALIAS';
  // All event samples must contain this source and at least one usable value.
  // A sparse heterogeneous sample or placeholders are not sufficient evidence
  // for a bulk-approved official field mapping.
  const informative=informativeValues.length;
  const high=compatibleObserved===informative&&values.length===events.length&&informative>0;
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
    explanation:high
      ?(method==='EXACT_DICTIONARY_NAME'
        ?'Source name matches the official Stellar metadata field and observed values match its documented type.'
        :'Reviewed source alias maps to an official Stellar metadata field and observed values match its documented type.')
      :values.length!==events.length
        ?'The field is missing from some events; review its event-family scope before applying an official mapping.'
        :informative===0
          ?'The source contains no informative values; a matching name alone is not enough to approve an official mapping.'
          :'The field-name match is plausible, but at least one observed value does not match the documented Stellar type.',
    catalogVerified:true,catalogRelease:'7.0.xs',observed:values.length,
    compatibleObserved,total:events.length,
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
