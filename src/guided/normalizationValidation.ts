import type {MappingRule,SuiteResult} from '../model';
import type {FieldGroup} from './contract';
import {lookupFieldValue,mappingWhenApplies} from '../fieldPaths';
import {officialProtocolPairConflict} from '../stellar7ValueConstraints';
import {findStellarMetadataField} from './stellarMetadataCatalog';
import {valueFitsMappingType,valueFitsNormalizationTarget} from './normalizationCandidates';

export type NormalizationFindingCode=
  'TARGET_COLLISION'|'TYPE_ERROR'|'SOURCE_NOT_FOUND'|'UNVERIFIED_TARGET'|
  'CATALOG_TYPE_MISMATCH'|'TARGET_RESERVED'|'BACKEND_TYPE_UNSUPPORTED'|'PROTOCOL_CONFLICT';

export interface NormalizationFinding {
  code:NormalizationFindingCode;
  source:string;
  target:string;
  event:number|null;
}

const MAX_REPORTED_FINDINGS=300;

export interface NormalizationReviewResult {
  findings:NormalizationFinding[];
  totalFindings:number;
  totalBlocking:number;
}

const BLOCKING_CODES=new Set<NormalizationFindingCode>([
  'TARGET_COLLISION','TYPE_ERROR','UNVERIFIED_TARGET','CATALOG_TYPE_MISMATCH',
  'TARGET_RESERVED','BACKEND_TYPE_UNSUPPORTED','PROTOCOL_CONFLICT',
]);
export function isBlockingNormalizationFinding(code:NormalizationFindingCode):boolean{
  return BLOCKING_CODES.has(code);
}

function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
}
export function reviewNormalizationMappings(
  suite:SuiteResult|undefined,mappings:MappingRule[],
  groups:Record<string,FieldGroup>={},
):NormalizationReviewResult{
  if(!suite)return {findings:[],totalFindings:0,totalBlocking:0};
  const findings:NormalizationFinding[]=[];
  for(const mapping of mappings){
    if(mappings.some(other=>other.id!==mapping.id&&overlaps(other.target,mapping.target)))
      findings.push({code:'TARGET_COLLISION',source:mapping.source,target:mapping.target,event:null});
    const group=groups[mapping.id];
    if(group!=='vendor_fields'&&!mapping.target.startsWith('custom.')){
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
      if(!mappingWhenApplies(fields,mapping.when))continue;
      const found=lookupFieldValue(fields,mapping.source,mapping.sourcePathKind);
      if(!found.found)findings.push({code:'SOURCE_NOT_FOUND',source:mapping.source,target:mapping.target,event:i+1});
      else if(!(groups[mapping.id]==='vendor_fields'
        // Vendor-local names can coincide with official Stellar names (for
        // example qualitative severity). Apply the chosen value type, not
        // an official field's numeric/range constraint, until the user
        // explicitly maps that field to the official Stellar namespace.
        ?valueFitsMappingType(mapping.type,found.value)
        :valueFitsNormalizationTarget(mapping.target,mapping.type,found.value)))
        findings.push({code:'TYPE_ERROR',source:mapping.source,target:mapping.target,event:i+1});
    }
  }
  const official=(target:string)=>mappings.find(m=>m.target===target&&
    ['top_fields','ns_fields'].includes(groups[m.id]??'vendor_fields'));
  const proto=official('proto'),name=official('proto_name');
  if(proto&&name)for(let i=0;i<suite.events.length;i++){
    const fields=suite.events[i]!.fields;
    const rawProto=lookupFieldValue(fields,proto.source,proto.sourcePathKind);
    const rawName=lookupFieldValue(fields,name.source,name.sourcePathKind);
    if(rawProto.found&&rawName.found&&
      officialProtocolPairConflict(rawProto.value,rawName.value))
      findings.push({code:'PROTOCOL_CONFLICT',source:name.source,target:'proto_name',event:i+1});
  }
  // Check all events before enforcing the display cap. Earlier nonblocking
  // absent-field notes must never hide a later invalid official field.
  const blocking=findings.filter(item=>isBlockingNormalizationFinding(item.code));
  const shown=findings.length<=MAX_REPORTED_FINDINGS?findings:[
    ...blocking.slice(0,MAX_REPORTED_FINDINGS),
    ...findings.filter(item=>!isBlockingNormalizationFinding(item.code))
      .slice(0,Math.max(0,MAX_REPORTED_FINDINGS-blocking.length)),
  ];
  return {findings:shown,totalFindings:findings.length,totalBlocking:blocking.length};
}

export function validateNormalizationMappings(
  suite:SuiteResult|undefined,mappings:MappingRule[],
  groups:Record<string,FieldGroup>={},
):NormalizationFinding[]{
  return reviewNormalizationMappings(suite,mappings,groups).findings;
}
