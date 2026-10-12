/**
 * Optional field-NAME-ONLY hints. Does not ingest a log event or field value.
 * Human review is mandatory before assigning a normalized output name.
 * No target, native runner, compiler or parser side effects.
 */
export class MappingSuggestionError extends Error{
  constructor(readonly code:string){super(code);this.name="MappingSuggestionError";}
}
const reject=(code:string):never=>{throw new MappingSuggestionError(code);};
const FIELD=/^[A-Za-z_][A-Za-z0-9_.-]{0,95}$/;
const BAD=new Set(["__proto__","constructor","prototype"]);
const aliases:ReadonlyArray<{
  destination:string;type:"string"|"ip"|"port";
  source:readonly string[];
}>=[
  {destination:"srcip",type:"ip",
    source:["src_ip","source.ip","srcip","source_ip","sourceip"]},
  {destination:"dstip",type:"ip",
    source:["dst_ip","destination.ip","dstip","destination_ip","dest_ip"]},
  {destination:"dstport",type:"port",
    source:["dst_port","destination.port","dest_port","dstport"]},
  {destination:"action",type:"string",
    source:["action","act","event.action"]},
  {destination:"username",type:"string",
    source:["username","user_name","user.name","account_name"]},
  {destination:"url",type:"string",
    source:["url","request_url","http.url"]},
];
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
    const mapping=aliases.find(a=>a.source.includes(field.toLowerCase()));
    if(!mapping){unknownFields.push(field);continue;}
    suggestions.push({
      sourceField:field,proposedDestination:mapping.destination,
      type:mapping.type,reason:"NAME_ALIAS_ONLY",status:"REVIEW_REQUIRED",
    });
  }
  const count=new Map<string,number>();
  for(const hint of suggestions)
    count.set(hint.proposedDestination,(count.get(hint.proposedDestination)??0)+1);
  for(const hint of suggestions){
    if(previous.has(hint.proposedDestination))hint.status="EXISTING_MAPPING";
    else if((count.get(hint.proposedDestination)??0)>1)
      hint.status="DESTINATION_CONFLICT";
  }
  return {contract:"parser-mapping-hints.v0.1",
    suggestions,unknownFields,containsRawValues:false,
    autoApplied:false,nativeVerified:false,targetImportVerified:false};
}
