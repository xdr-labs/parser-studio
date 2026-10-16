import type {MappingRule,SuiteResult} from '../model';
import {lookupFieldValue} from '../fieldPaths';
import {findStellarMetadataField} from './stellarMetadataCatalog';
import {valueFitsMappingType} from './normalizationCandidates';

export type NormalizationFindingCode=
  'TARGET_COLLISION'|'TYPE_ERROR'|'SOURCE_NOT_FOUND'|'UNVERIFIED_TARGET'|
  'CATALOG_TYPE_MISMATCH'|'TARGET_RESERVED'|'BACKEND_TYPE_UNSUPPORTED';

export interface NormalizationFinding {
  code:NormalizationFindingCode;
  source:string;
  target:string;
  event:number|null;
}

function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
}
export function validateNormalizationMappings(
  suite:SuiteResult|undefined,mappings:MappingRule[],
):NormalizationFinding[]{
  if(!suite)return [];
  const findings:NormalizationFinding[]=[];
  for(const mapping of mappings){
    if(mappings.some(other=>other.id!==mapping.id&&overlaps(other.target,mapping.target)))
      findings.push({code:'TARGET_COLLISION',source:mapping.source,target:mapping.target,event:null});
    if(!mapping.target.startsWith('custom.')){
      const catalog=findStellarMetadataField(mapping.target);
      if(!catalog){
        findings.push({code:'UNVERIFIED_TARGET',source:mapping.source,target:mapping.target,event:null});
      }else if(catalog.reason==='RESERVED_RUNTIME_FIELD'){
        findings.push({code:'TARGET_RESERVED',source:mapping.source,target:mapping.target,event:null});
      }else if(!catalog.mappable||!catalog.mappingType){
        findings.push({code:'BACKEND_TYPE_UNSUPPORTED',source:mapping.source,target:mapping.target,event:null});
      }else if(mapping.type!==catalog.mappingType){
        findings.push({code:'CATALOG_TYPE_MISMATCH',source:mapping.source,target:mapping.target,event:null});
      }
    }
  }
  for(let i=0;i<suite.events.length;i++){
    const fields=suite.events[i]!.fields;
    for(const mapping of mappings){
      const found=lookupFieldValue(fields,mapping.source);
      if(!found.found)findings.push({code:'SOURCE_NOT_FOUND',source:mapping.source,target:mapping.target,event:i+1});
      else if(!valueFitsMappingType(mapping.type,found.value))
        findings.push({code:'TYPE_ERROR',source:mapping.source,target:mapping.target,event:i+1});
    }
  }
  return findings.slice(0,300);
}
