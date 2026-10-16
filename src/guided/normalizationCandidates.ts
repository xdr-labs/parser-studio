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
  spt:'srcport',src_port:'srcport',source_port:'srcport',sourceport:'srcport',
  srcport:'srcport','source.port':'srcport',client_port:'srcport',
  'body.spt':'srcport','body.srcport':'srcport','body.src_port':'srcport',
  dpt:'dstport',dst_port:'dstport',destination_port:'dstport',destinationport:'dstport',
  dest_port:'dstport',destport:'dstport',dstport:'dstport',
  'destination.port':'dstport',server_port:'dstport',
  'body.dpt':'dstport','body.dstport':'dstport','body.dst_port':'dstport',
  act:'action',event_action:'action',eventaction:'action','event.action':'action',
  'body.act':'action','body.action':'action',
  event_time:'timestamp',eventtime:'timestamp','event.time':'timestamp','event.timestamp':'timestamp',
  '@timestamp':'timestamp',syslog_timestamp:'timestamp',
  host_name:'hostname',hostname:'hostname','host.name':'hostname',device_name:'hostname',
  devicename:'hostname','device.hostname':'hostname',syslog_hostname:'hostname',
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
function candidateForSource(source:string,events:Record<string,unknown>[],existing:MappingRule[]):NormalizationCandidate|null{
  const exact=findStellarMetadataField(source);
  const target=exact?.mappable?source:ALIASES[source.toLowerCase()];
  if(!target)return null;
  const catalog=findStellarMetadataField(target);
  if(!catalog?.mappable||!catalog.mappingType||!catalog.group)return null;
  const current=existing.find(rule=>rule.source===source);
  if(current&&current.target===target&&current.type===catalog.mappingType)return null;
  if(existing.some(rule=>rule.id!==current?.id&&overlaps(rule.target,target)))return null;
  const values=events.map(fields=>lookupFieldValue(fields,source)).filter(result=>result.found);
  if(values.length===0)return null;
  const compatible=values.filter(result=>result.found&&
    valueFitsNormalizationTarget(target,catalog.mappingType!,result.value)).length;
  const method:NormalizationCandidate['method']=target===source?'EXACT_DICTIONARY_NAME':'DOCUMENTED_ALIAS';
  const high=compatible===values.length;
  const defaultGenerated=new Map([
    ['source-ip','custom.source_ip'],['target-port','custom.destination_port'],['action','custom.action'],
  ]);
  const replaceIsGenerated=Boolean(current&&current.target.startsWith('custom.')&&(
    current.id.startsWith('auto-')||defaultGenerated.get(current.id)===current.target
  ));
  return {
    source,target,type:catalog.mappingType,group:catalog.group,
    confidence:high?'HIGH':'REVIEW',method,
    explanation:high
      ?(method==='EXACT_DICTIONARY_NAME'
        ?'Source name matches the official Stellar metadata field and observed values match its documented type.'
        :'Reviewed source alias maps to an official Stellar metadata field and observed values match its documented type.')
      :'The field-name match is plausible, but at least one observed value does not match the documented Stellar type.',
    catalogVerified:true,catalogRelease:'7.0.xs',observed:values.length,total:events.length,
    ...(current?{replacesMappingId:current.id,currentTarget:current.target}:{}),
    safeForBulk:high&&(!current||replaceIsGenerated),
  };
}
export function suggestNormalizationCandidatesFromSuite(
  suite:SuiteResult|undefined,existing:MappingRule[],
):NormalizationCandidate[]{
  if(!suite?.events.length)return [];
  const fields=suite.events.map(event=>event.fields);
  const sources=new Set<string>();
  for(const event of fields)for(const path of listSafeLeafPaths(event))sources.add(path);
  const proposed:NormalizationCandidate[]=[];
  const targets=new Set<string>();
  for(const source of [...sources].slice(0,100)){
    const candidate=candidateForSource(source,fields,existing);
    if(!candidate||targets.has(candidate.target))continue;
    proposed.push(candidate);targets.add(candidate.target);
  }
  return proposed;
}

/** Backward-compatible selected-event helper used by the Review Fields summary. */
export function suggestNormalizationCandidates(
  fields:Record<string,unknown>,existing:MappingRule[],
):NormalizationCandidate[]{
  const suite={events:[{fields}]} as unknown as SuiteResult;
  return suggestNormalizationCandidatesFromSuite(suite,existing);
}
