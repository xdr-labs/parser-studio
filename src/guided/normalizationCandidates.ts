import type {MappingRule,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
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
  src_ip:'srcip',source_ip:'srcip','source.ip':'srcip','source.address':'srcip',
  client_ip:'srcip','client.ip':'srcip',
  dst_ip:'dstip',destination_ip:'dstip',dest_ip:'dstip','destination.ip':'dstip',
  'destination.address':'dstip',server_ip:'dstip','server.ip':'dstip',
  src_port:'srcport',source_port:'srcport','source.port':'srcport',client_port:'srcport',
  dst_port:'dstport',destination_port:'dstport',dest_port:'dstport',
  'destination.port':'dstport',server_port:'dstport',
  event_action:'action','event.action':'action',
  event_time:'timestamp','event.time':'timestamp','event.timestamp':'timestamp',
  '@timestamp':'timestamp',
  host_name:'hostname','host.name':'hostname',device_name:'hostname',
  'device.hostname':'hostname',
};

function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
}
function ignored(value:unknown):boolean{
  return value===null||value===undefined||['','N/A','-'].includes(String(value));
}
export function valueFitsMappingType(type:MappingRule['type'],value:unknown):boolean{
  if(ignored(value))return true;
  if(type==='string')return typeof value==='string'||typeof value==='number'||typeof value==='boolean';
  if(type==='ip')return typeof value==='string'&&/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)&&
    value.split('.').every(part=>Number(part)<=255);
  if(type==='port')return /^\d+$/.test(String(value))&&Number(value)>=0&&Number(value)<=65535;
  if(type==='integer')return /^-?\d+$/.test(String(value))&&Number.isSafeInteger(Number(value));
  if(type==='number')return String(value).trim()!==''&&Number.isFinite(Number(value));
  if(type==='boolean')return typeof value==='boolean'||['true','false'].includes(String(value).toLowerCase());
  if(type==='timestamp')return typeof value==='string'&&/^\d{4}-\d\d-\d\d[T ]/.test(value)&&
    Number.isFinite(Date.parse(value));
  return false;
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
  const compatible=values.filter(result=>result.found&&valueFitsMappingType(catalog.mappingType!,result.value)).length;
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
