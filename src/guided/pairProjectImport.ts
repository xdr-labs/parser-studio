import type { ParserDraft, MappingRule } from '../model';
import {isGenericStructuralProfile} from '../genericStructuralProfiles';
import { defaultGuidedOptions, type EventClass, type FieldGroup, type GuidedEnrichmentRule } from './contract';
import { toBackendProject, type BackendParserProject } from './backendAdapter';

/**
 * Reverse only the EXACT, reviewed Parser Studio backend project subset.
 * A foreign Ruby fragment, incompatible model, lossy/ambiguous rule or extra
 * field NEVER yields a new editable draft. Import is manual; raw logs and
 * original vendor source are intentionally excluded.
 */
const PAIR=/^customized_[a-z][a-z0-9_]{1,47}$/;
const GROUPS=[
  ['topFields','top_fields'],['nsFields','ns_fields'],['vendorFields','vendor_fields'],
] as const;
const INDEX: Record<string,EventClass>={
  session:'Session',threat:'Threat',syslog:'Syslog',winlogevent:'Winlogevent',
};
const SOURCE_TYPES=new Set(['string','integer','ip','port','boolean','date']);
const ENRICHMENT_TYPES=new Set(['set_const','copy','lowercase','uppercase','split_field','merge_fields']);
const isObject=(value:unknown):value is Record<string,unknown> =>
  value!==null && typeof value==='object' && !Array.isArray(value);

function normalize(value:unknown):unknown {
  if(Array.isArray(value))return value.map(normalize);
  if(!isObject(value))return value;
  return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,normalize(value[key])]),
  );
}

/** Returns null rather than silently dropping unsupported backend semantics. */
export function reconstructExactBackendDraft(
  input:unknown,pairName:string,
):ParserDraft|null {
  if(!PAIR.test(pairName) || !isObject(input))return null;
  try{
    const bytes=new TextEncoder().encode(JSON.stringify(input));
    if(bytes.length>262144)return null;
    const p=input as unknown as BackendParserProject;
    if(p.schemaRevision!=='0.1' || p.revision!==1 ||
      p.projectId!=='draft-'+p.slug ||
      pairName!=='customized_'+p.slug ||
      typeof p.vendor!=='string' || typeof p.product!=='string' ||
      !p.vendor.trim() || !p.product.trim() ||
      (p.productVersion!==undefined&&(typeof p.productVersion!=='string'||!p.productVersion.trim())) ||
      !isObject(p.extraction) || !isObject(p.receiver) ||
      !isObject(p.normalization) || !isObject(p.classification))return null;
    const options=defaultGuidedOptions();
    if(!Array.isArray(p.receiver.protocols) ||
      !p.receiver.protocols.every(v=>v==='udp'||v==='tcp') ||
      (p.receiver.bindAddress!=='0.0.0.0'&&p.receiver.bindAddress!=='127.0.0.1') ||
      p.receiver.tcpFraming!=='line')return null;
    if(!['json','kv','csv','cef','leef','syslog_rfc5424'].includes(p.extraction.format)&&
      !(p.extraction.format==='generic_structural'&&isGenericStructuralProfile(p.extraction.genericStructuralProfile)))
      return null;
    const mappings:MappingRule[]=[];
    const groups:Record<string,FieldGroup>=Object.create(null);
    const indexedTargets=new Map<string,string>();
    for(const [backendName,uiName] of GROUPS){
      const fields=p.normalization[backendName];
      if(!isObject(fields)||Object.keys(fields).length>80)return null;
      for(const [source,description] of Object.entries(fields)){
        if(!isObject(description) || typeof description.normalized_name!=='string' ||
          !SOURCE_TYPES.has(String(description.data_type)))return null;
        const id='imported-'+(mappings.length+1);
        const type=description.data_type==='date'?'timestamp':description.data_type as MappingRule['type'];
        mappings.push({id,source,target:description.normalized_name,type});
        groups[id]=uiName;
        if(uiName!=='vendor_fields'){
          if(indexedTargets.has(description.normalized_name))return null;
          indexedTargets.set(description.normalized_name,source);
        }
      }
    }
    if(mappings.length<1 || mappings.length>80 ||
      !Array.isArray(p.classification.rules) || p.classification.rules.length>100 ||
      !INDEX[p.classification.defaultIndex])return null;
    const rules=[];
    for(const [i,rule] of p.classification.rules.entries()){
      if(!isObject(rule) || rule.operator!=='equals' ||
        !INDEX[rule.index] || typeof rule.value!=='string' ||
        typeof rule.field!=='string')return null;
      const source=indexedTargets.get(rule.field);
      if(!source)return null;
      rules.push({id:'imported-rule-'+(i+1),
        sourceField:source,equals:rule.value,index:INDEX[rule.index]});
    }
    const enrichment:GuidedEnrichmentRule[]=[];
    if(p.enrichment!==undefined){
      if(!Array.isArray(p.enrichment)||p.enrichment.length>64)return null;
      for(const [i,rule] of p.enrichment.entries()){
        if(!isObject(rule)||!ENRICHMENT_TYPES.has(String(rule.operator)))return null;
        const id='imported-enrichment-'+(i+1);
        if(rule.operator==='set_const'){
          if(typeof rule.target!=='string'||typeof rule.value!=='string')return null;
          enrichment.push({id,operator:'set_const',source:'',target:rule.target,value:rule.value});
        }else if(rule.operator==='split_field'){
          if(typeof rule.source!=='string'||typeof rule.delimiter!=='string'||
            !Array.isArray(rule.targets)||rule.targets.length<2||rule.targets.length>8||
            !rule.targets.every(target=>typeof target==='string'))return null;
          enrichment.push({id,operator:'split_field',source:rule.source,target:'',value:'',
            delimiter:rule.delimiter,targets:[...rule.targets]});
        }else if(rule.operator==='merge_fields'){
          if(!Array.isArray(rule.sources)||rule.sources.length<2||rule.sources.length>8||
            !rule.sources.every(source=>typeof source==='string')||
            typeof rule.delimiter!=='string'||typeof rule.target!=='string')return null;
          enrichment.push({id,operator:'merge_fields',source:'',target:rule.target,value:'',
            delimiter:rule.delimiter,sources:[...rule.sources]});
        }else{
          if(typeof rule.source!=='string'||typeof rule.target!=='string')return null;
          enrichment.push({id,operator:rule.operator,source:rule.source,target:rule.target,value:''});
        }
      }
    }
    const e=p.extraction;
    const draft:ParserDraft={
      name:p.product,vendor:p.vendor,version:p.productVersion,format:e.format,
      pattern:'',csvColumns:e.format==='csv'?e.csvColumns.join(','):'',
      csvDelimiter:e.format==='csv'?e.csvDelimiter:',',
      syslogBodyFormat:e.format==='syslog_rfc5424'?e.syslogBodyFormat??'raw':'raw',
      ...(e.genericStructuralProfile?{genericStructuralProfile:e.genericStructuralProfile}:{}),
      ...(e.format==='generic_structural'&&e.omitSourceRaw===true?{omitSourceRaw:true as const}:{}),
      mappings,
      guided:{
        ...options,
        slug:p.slug,
        sourceCategory:p.sourceCategory,
        groups,
        receiver:{
          protocols:[...p.receiver.protocols],
          port:p.receiver.port,
          bindPolicy:p.receiver.bindAddress==='0.0.0.0'?'all':'loopback',
          messageLimit:p.receiver.messageLengthLimit,
          framing:'newline',
        },
        classification:{defaultIndex:INDEX[p.classification.defaultIndex],rules},
        enrichment,
      },
    };
    const roundTrip=toBackendProject(draft);
    if(!roundTrip.ok || JSON.stringify(normalize(roundTrip.project))!==
      JSON.stringify(normalize(input)))return null;
    return draft;
  }catch{return null;}
}
