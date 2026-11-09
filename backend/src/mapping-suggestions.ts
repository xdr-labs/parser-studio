/**
 * Optional field-NAME-ONLY hints. Does not ingest a log event or field value.
 * Human review is mandatory before assigning a normalized output name.
 * No target, native runner, compiler or parser side effects.
 */
import semanticPolicy from "../semantic-policy.v1.json" with {type:"json"};

export class MappingSuggestionError extends Error{
  constructor(readonly code:string){super(code);this.name="MappingSuggestionError";}
}
const reject=(code:string):never=>{throw new MappingSuggestionError(code);};
const FIELD=/^[A-Za-z_][A-Za-z0-9_.-]{0,95}$/;
const BAD=new Set(["__proto__","constructor","prototype"]);
// Approved name identities derive from the frontend normalization policy.
// Name-only evidence always requires review; never auto-apply to records.
const APPROVED=new Set<string>(semanticPolicy.advisoryNameOnlySources);
const TYPES:Readonly<Record<string,"string"|"ip"|"port">>=
  semanticPolicy.advisoryTargetTypes as Record<string,"string"|"ip"|"port">;
const NORMALIZATION:Readonly<Record<string,string>>=semanticPolicy.normalizationAliases;
const ADVISORY_ONLY:Readonly<Record<string,string>>=semanticPolicy.advisoryOnlyAliases;
const EXPLICIT_PORT:Readonly<Record<string,string>>=semanticPolicy.explicitPortSourceAliases;
const TRANSLATED=new Set<string>(semanticPolicy.excludedPortSourceSegments);
function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+".")||b.startsWith(a+".");
}
function excludedPortSource(path:string):boolean{
  return path.split(".").some(segment=>{
    const normalized=segment.replace(/([a-z0-9])([A-Z])/g,"$1_$2").toLowerCase();
    return normalized.split(/[-_]+/).some(token=>TRANSLATED.has(token));
  });
}
function reviewOnlyDestination(field:string):string|undefined{
  const lower=field.toLowerCase();
  const leaf=lower.split(".").at(-1)!;
  const destination=APPROVED.has(lower)?
    NORMALIZATION[lower]??ADVISORY_ONLY[lower]:EXPLICIT_PORT[leaf];
  // Preserve NAT/translated paths as source data regardless of leaf spelling.
  if((destination==="srcport"||destination==="dstport")&&
     excludedPortSource(field))return undefined;
  return destination;
}

export type MappingHintInput={
  fieldNames:string[];
  existingDestinations?:string[];
};
export type MappingHint={
  sourceField:string;
  proposedDestination:string;
  type:"string"|"ip"|"port";
  reason:"NAME_ALIAS_ONLY";
  status:"REVIEW_REQUIRED"|"DESTINATION_CONFLICT"|"EXISTING_MAPPING";
};
export type MappingHintReport={
  contract:"parser-mapping-hints.v0.1";
  suggestions:MappingHint[];
  unknownFields:string[];
  containsRawValues:false;
  autoApplied:false;
  nativeVerified:false;
  targetImportVerified:false;
};
function validNames(list:unknown,max:number):list is string[]{
  return Array.isArray(list)&&list.length<=max&&
    list.every(x=>typeof x==="string"&&FIELD.test(x)&&
      x.split(".").every(p=>p.length>0&&!BAD.has(p)))&&
    new Set(list).size===list.length;
}
export function suggestFieldMappings(input:MappingHintInput):MappingHintReport{
  if(!input||typeof input!=="object"||Array.isArray(input)||
     Object.keys(input).some(k=>k!=="fieldNames"&&k!=="existingDestinations")||
     !validNames(input.fieldNames,100)||
     (input.existingDestinations!==undefined&&
       !validNames(input.existingDestinations,100)))
    reject("MAPPING_INPUT_INVALID");
  const previous=new Set(input.existingDestinations??[]);
  const sorted=[...input.fieldNames].sort();
  const suggestions:MappingHint[]=[];
  const unknownFields:string[]=[];
  for(const field of sorted){
    const destination=reviewOnlyDestination(field);
    if(!destination||!TYPES[destination]){unknownFields.push(field);continue;}
    suggestions.push({
      sourceField:field,proposedDestination:destination,
      type:TYPES[destination]!,reason:"NAME_ALIAS_ONLY",status:"REVIEW_REQUIRED",
    });
  }
  for(const hint of suggestions){
    if(previous.has(hint.proposedDestination))
      hint.status="EXISTING_MAPPING";
    else if([...previous].some(value=>overlaps(value,hint.proposedDestination))||
      suggestions.some(other=>other!==hint&&
        overlaps(other.proposedDestination,hint.proposedDestination)))
      hint.status="DESTINATION_CONFLICT";
  }
  return {contract:"parser-mapping-hints.v0.1",
    suggestions,unknownFields,containsRawValues:false,
    autoApplied:false,nativeVerified:false,targetImportVerified:false};
}
