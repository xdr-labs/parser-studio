import type {MappingRule,ParserDraft} from '../model';
import {sha256Utf8Hex} from '../sha256';

export interface MappingExtensionChange{
  operation:'UPSERT';
  mappingId:string;
  source:string;
  target:string;
  type:MappingRule['type'];
  group:string;
}

export interface ParserMappingExtension{
  contract:'parser-studio.mapping-extension.v0.1';
  baseDraftSha256:string;
  vendor:string;
  product:string;
  productVersion:string;
  parserSlug:string;
  baseMappingCount:number;
  changes:MappingExtensionChange[];
  sourceValuesIncluded:false;
  extractionChanged:false;
  nativeVerified:false;
  targetVerified:false;
}

export type ParserExtensionBuildResult=
 |{ok:true;extension:ParserMappingExtension}
 |{ok:false;reason:'NO_CHANGES'|'UNSAFE_BASE_CHANGE'|'INVALID_MAPPING_SET'};

const VALID_GROUPS=new Set(['top_fields','ns_fields','vendor_fields']);
const VALID_TYPES=new Set(['string','integer','number','boolean','ip','port','timestamp']);
const SAFE_ID=/^[A-Za-z0-9_.:-]{1,128}$/;
const SAFE_PATH=/^[A-Za-z_][A-Za-z0-9_.@:\-[\]]{0,255}$/;

function safeChange(change:MappingExtensionChange):boolean{
  return change.operation==='UPSERT'&&SAFE_ID.test(change.mappingId)&&
    SAFE_PATH.test(change.source)&&SAFE_PATH.test(change.target)&&
    VALID_TYPES.has(change.type)&&VALID_GROUPS.has(change.group);
}

function stable(value:unknown):unknown{
  if(Array.isArray(value))return value.map(stable);
  if(value&&typeof value==='object'){
    const record=value as Record<string,unknown>;
    return Object.fromEntries(Object.keys(record).sort().map(key=>[key,stable(record[key])]));
  }
  return value;
}

function withoutMappingOverlay(draft:ParserDraft):unknown{
  const guided=draft.guided?{...draft.guided,groups:{}}:undefined;
  return stable({...draft,mappings:[],guided});
}

function canonicalDraft(draft:ParserDraft):string{
  return JSON.stringify(stable(draft));
}

function groupOf(draft:ParserDraft,id:string):string{
  return draft.guided?.groups[id]??'vendor_fields';
}

function safeMappingSet(draft:ParserDraft):boolean{
  if(draft.mappings.length>80)return false;
  const ids=new Set<string>();
  for(const mapping of draft.mappings){
    const group=groupOf(draft,mapping.id);
    if(!SAFE_ID.test(mapping.id)||ids.has(mapping.id)||
       !SAFE_PATH.test(mapping.source)||!SAFE_PATH.test(mapping.target)||
       !VALID_TYPES.has(mapping.type)||!VALID_GROUPS.has(group))return false;
    ids.add(mapping.id);
  }
  return true;
}

export async function buildMappingExtension(
  base:ParserDraft,current:ParserDraft,
):Promise<ParserExtensionBuildResult>{
  if(!safeMappingSet(base)||!safeMappingSet(current))return {ok:false,reason:'INVALID_MAPPING_SET'};
  if(JSON.stringify(withoutMappingOverlay(base))!==JSON.stringify(withoutMappingOverlay(current)))
    return {ok:false,reason:'UNSAFE_BASE_CHANGE'};

  const currentById=new Map(current.mappings.map(mapping=>[mapping.id,mapping] as const));
  const baseIds=new Set(base.mappings.map(mapping=>mapping.id));
  const changes:MappingExtensionChange[]=[];

  for(const original of base.mappings){
    const next=currentById.get(original.id);
    if(!next||next.source!==original.source)return {ok:false,reason:'UNSAFE_BASE_CHANGE'};
    if(next.target!==original.target||next.type!==original.type||
       groupOf(current,next.id)!==groupOf(base,original.id)){
      changes.push({operation:'UPSERT',mappingId:next.id,source:next.source,
        target:next.target,type:next.type,group:groupOf(current,next.id)});
    }
  }
  for(const mapping of current.mappings){
    if(baseIds.has(mapping.id))continue;
    changes.push({operation:'UPSERT',mappingId:mapping.id,source:mapping.source,
      target:mapping.target,type:mapping.type,group:groupOf(current,mapping.id)});
  }
  if(!changes.length)return {ok:false,reason:'NO_CHANGES'};

  return {ok:true,extension:{
    contract:'parser-studio.mapping-extension.v0.1',
    baseDraftSha256:await sha256Utf8Hex(canonicalDraft(base)),
    vendor:base.vendor,product:base.name,productVersion:base.version??'',
    parserSlug:base.guided?.slug??'',
    baseMappingCount:base.mappings.length,
    changes,
    sourceValuesIncluded:false,extractionChanged:false,
    nativeVerified:false,targetVerified:false,
  }};
}

export async function applyMappingExtension(
  base:ParserDraft,extension:ParserMappingExtension,
):Promise<ParserDraft|null>{
  if(extension.contract!=='parser-studio.mapping-extension.v0.1'||
     extension.sourceValuesIncluded!==false||extension.extractionChanged!==false||
     extension.nativeVerified!==false||extension.targetVerified!==false||
     extension.baseDraftSha256!==await sha256Utf8Hex(canonicalDraft(base))||
     extension.vendor!==base.vendor||extension.product!==base.name||
     extension.productVersion!==(base.version??'')||
     extension.parserSlug!==(base.guided?.slug??'')||
     extension.baseMappingCount!==base.mappings.length||
     extension.changes.length>80)return null;
  const options=base.guided?{...base.guided,groups:{...base.guided.groups}}:undefined;
  const mappings=base.mappings.map(mapping=>({...mapping}));
  for(const change of extension.changes){
    if(!safeChange(change))return null;
    const index=mappings.findIndex(mapping=>mapping.id===change.mappingId);
    if(index>=0){
      if(mappings[index]!.source!==change.source)return null;
      mappings[index]={id:change.mappingId,source:change.source,target:change.target,type:change.type};
    }else mappings.push({id:change.mappingId,source:change.source,target:change.target,type:change.type});
    if(options)options.groups[change.mappingId]=change.group as never;
  }
  return {...base,mappings,guided:options};
}
