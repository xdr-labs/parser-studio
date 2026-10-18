import {createHash} from 'node:crypto';

/**
 * Source-only observer for externally bounded "Label: Value, Label: Value".
 *
 * The annotation may identify an intact excerpt of a truncated or concatenated
 * collector record; it NEVER proves an event boundary, physical sender, actual
 * wire transmission, schema semantics, or a complete/full native parse.
 *
 * Delimiter handling is deliberately conservative: without a declared
 * producer rule, any ambiguous embedded comma, open quote or malformed field
 * is rejected instead of silently losing or shifting data.
 */
export interface BoundedColonSourceInput{
  sourceBytes:Uint8Array;
  sourceSha256:string;
  analysisScope:string;
  boundedStartByte:number;
  boundedEndByte:number;
  boundedSliceSha256:string;
}
export interface ColonSourceField{
  name:string;
  occurrence:number;
  rawLexeme:string;
  sourceValue:string;
  nameStartByte:number;
  nameEndByte:number;
  valueStartByte:number;
  valueEndByte:number;
}
export type ColonSourceDisposition=
  'RAW_ONLY'|'ABSTAIN_UNSAFE'|'REVIEW_ONLY_PARTIAL_LABELS';
export interface ColonSourceReview {
  disposition:ColonSourceDisposition;
  sourceBytes:number;
  selectedBodyRange:{startByte:number;endByte:number}|null;
  unreviewedPrefixBytes:number;
  unreviewedSuffixBytes:number;
  fields:ColonSourceField[];
  sourceComplete:false;
  nativeVerified:false;
  independentOracleCertified:false;
  canAutoPromote:false;
  manufacturerSemantics:'NOT_CERTIFIED';
  originalDeviceIdentity:'NOT_ATTESTED';
  transportPeerAuthentication:'NOT_VERIFIED';
}
const MAX_SOURCE_BYTES=64*1024;
const MAX_SLICE_BYTES=16*1024;
const MAX_FIELDS=128;
const SHA256=/^[0-9a-f]{64}$/;
const KEY=/^[A-Za-z][A-Za-z0-9_ ./()#-]{0,127}$/;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const hash=(bytes:Uint8Array)=>
  createHash('sha256').update(bytes).digest('hex');
const validHash=(value:string,bytes:Uint8Array)=>
  SHA256.test(value)&&hash(bytes)===value;

export function inspectBoundedColonLabels(input:BoundedColonSourceInput):ColonSourceReview{
  const raw=input.sourceBytes;
  const sourceBytes=raw instanceof Uint8Array?raw.length:0;
  const base:ColonSourceReview={
    disposition:'ABSTAIN_UNSAFE',sourceBytes,
    selectedBodyRange:null,unreviewedPrefixBytes:sourceBytes,
    unreviewedSuffixBytes:0,fields:[],
    sourceComplete:false,nativeVerified:false,
    independentOracleCertified:false,canAutoPromote:false,
    manufacturerSemantics:'NOT_CERTIFIED',originalDeviceIdentity:'NOT_ATTESTED',
    transportPeerAuthentication:'NOT_VERIFIED',
  };
  if(input.analysisScope!=='EXPLICIT_SUBRECORD_SOURCE_SLICE')
    return {...base,disposition:'RAW_ONLY'};
  if(!(raw instanceof Uint8Array)||!sourceBytes||sourceBytes>MAX_SOURCE_BYTES||
     !validHash(input.sourceSha256,raw)||
     !Number.isInteger(input.boundedStartByte)||
     !Number.isInteger(input.boundedEndByte)||
     input.boundedStartByte<1||
     input.boundedStartByte>=input.boundedEndByte||
     input.boundedEndByte>sourceBytes||
     input.boundedEndByte-input.boundedStartByte>MAX_SLICE_BYTES)
    return base;
  const start=input.boundedStartByte;
  const end=input.boundedEndByte;
  const slice=raw.subarray(start,end);
  if(!validHash(input.boundedSliceSha256,slice))return base;
  let original:string,prefix:string,selected:string,suffix:string;
  try{
    original=decoder.decode(raw);
    prefix=decoder.decode(raw.subarray(0,start));
    selected=decoder.decode(slice);
    suffix=decoder.decode(raw.subarray(end));
  }catch{return base;}
  // Reject a BOM round-trip loss, invalid UTF-8 boundary or replacement.
  if(!original.startsWith(prefix+selected)||
     prefix+selected+suffix!==original||
     encoder.encode(original).byteLength!==sourceBytes||
     encoder.encode(prefix).byteLength!==start||
     encoder.encode(selected).byteLength!==slice.length)
    return base;
  // A mark may not start mid-token or silently hide earlier comma-labelled
  // fields in the marked prefix. Do not infer claimed record framing.
  if(!/[ \t]$/.test(prefix)||prefix.includes(', ')||
     suffix!==''&&!suffix.startsWith(', ')||
     /[\0\r\n]/.test(original)||
     /<\d{1,3}>/.test(selected))
    return base;
  if(!selected||selected!==selected.trim()||
     selected.includes('\t')||/[\x00-\x1f\x7f]/.test(selected))
    return base;
  const textParts=selected.split(', ');
  if(textParts.length<2||textParts.length>MAX_FIELDS)return base;
  const fields:ColonSourceField[]=[];
  const keys=new Map<string,{canonical:string;next:number}>();
  let cursor=0;
  for(const [index,part] of textParts.entries()){
    if(!part||part.includes(',')||part.includes('\n')||part.includes('\r'))
      return base;
    const pivot=part.indexOf(': ');
    if(pivot<1)return base;
    const name=part.slice(0,pivot);
    const value=part.slice(pivot+2);
    if(!KEY.test(name)||name.trim()!==name||
       !value||value.trim()!==value||
       value.includes('\0')||
       (value.match(/"/g)?.length??0)%2!==0||
       (value.match(/'/g)?.length??0)%2!==0||
       /<\d{1,3}>/.test(value))
      return base;
    const normalized=name.toLowerCase().replaceAll('-','_');
    const prior=keys.get(normalized);
    if(prior&&prior.canonical!==name)return base;
    const occurrence=prior?.next??0;
    keys.set(normalized,{canonical:name,next:occurrence+1});
    const segmentStart=start+encoder.encode(selected.slice(0,cursor)).length;
    const nameEnd=segmentStart+encoder.encode(name).length;
    const valueStart=nameEnd+2;
    const valueEnd=valueStart+encoder.encode(value).length;
    if(valueEnd>sourceBytes||
       decoder.decode(raw.subarray(segmentStart,nameEnd))!==name||
       decoder.decode(raw.subarray(valueStart,valueEnd))!==value)
      return base;
    fields.push({name,occurrence,rawLexeme:value,sourceValue:value,
      nameStartByte:segmentStart,nameEndByte:nameEnd,
      valueStartByte:valueStart,valueEndByte:valueEnd});
    cursor+=part.length+(index<textParts.length-1?2:0);
  }
  if(cursor!==selected.length||fields.length!==textParts.length)
    return base;
  return {
    ...base,disposition:'REVIEW_ONLY_PARTIAL_LABELS',
    selectedBodyRange:{startByte:start,endByte:end},
    unreviewedPrefixBytes:start,unreviewedSuffixBytes:sourceBytes-end,
    fields,
  };
}
