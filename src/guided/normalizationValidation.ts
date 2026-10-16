import type {MappingRule,SuiteResult} from '../model';
export interface NormalizationFinding {code:'TARGET_COLLISION'|'TYPE_ERROR'|'SOURCE_NOT_FOUND'|'UNVERIFIED_TARGET';source:string;target:string;event:number;}
const valid=(type:MappingRule['type'],value:unknown):boolean=>{
 if(type==='string')return value!==null&&value!==undefined;
 if(type==='ip')return typeof value==='string'&&/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)&&value.split('.').every(x=>Number(x)<=255);
 if(type==='port')return /^\d+$/.test(String(value))&&Number(value)>=0&&Number(value)<=65535;
 if(type==='integer')return /^-?\d+$/.test(String(value))&&Number.isSafeInteger(Number(value));
 if(type==='number')return value!==null&&String(value).trim()!==''&&Number.isFinite(Number(value));
 if(type==='boolean')return typeof value==='boolean'||['true','false'].includes(String(value).toLowerCase());
 if(type==='timestamp')return typeof value==='string'&&/^\d{4}-\d\d-\d\dT/.test(value)&&Number.isFinite(Date.parse(value));
 return false;
};
export function validateNormalizationMappings(suite:SuiteResult|undefined,mappings:MappingRule[]):NormalizationFinding[]{
 if(!suite)return [];
 const findings:NormalizationFinding[]=[];
 for(let i=0;i<suite.events.length;i++){
  const fields=suite.events[i]!.fields;
  for(const mapping of mappings){
   const conflicts=mappings.filter(x=>x.id!==mapping.id&&(x.target===mapping.target||x.target.startsWith(mapping.target+'.')||mapping.target.startsWith(x.target+'.')));
   if(conflicts.length)findings.push({code:'TARGET_COLLISION',source:mapping.source,target:mapping.target,event:i+1});
   if(!Object.prototype.hasOwnProperty.call(fields,mapping.source))findings.push({code:'SOURCE_NOT_FOUND',source:mapping.source,target:mapping.target,event:i+1});
   else if(!valid(mapping.type,fields[mapping.source]))findings.push({code:'TYPE_ERROR',source:mapping.source,target:mapping.target,event:i+1});
   if(!mapping.target.startsWith('custom.'))findings.push({code:'UNVERIFIED_TARGET',source:mapping.source,target:mapping.target,event:i+1});
  }
 }
 return findings.slice(0,200);
}
