import type {MultiPassSourcePreview} from './multipassPreviewClient';
import {fromSourceByteRange} from './sourceByteSelection';

export type MultiPassSourceSelection={
 kind:'field'|'residual';startByte:number;endByte:number;path?:string;text:string;
};
export type MultiPassSourceSegment=
 | {kind:'plain';text:string}
 | {kind:'field'|'residual';text:string;selection:MultiPassSourceSelection};
export type MultiPassSourceHighlightResult=
 | {ok:true;segments:MultiPassSourceSegment[];selectable:MultiPassSourceSelection[]}
 | {ok:false;reason:'INVALID_RANGE'|'AMBIGUOUS_FIELD_OVERLAP'|'AMBIGUOUS_RESIDUAL_OVERLAP'|'SOURCE_RECONSTRUCTION_FAILED'};

/**
 * Build a lossless UTF-8-byte-aware source map from the trusted Multi-Pass preview.
 * A residual may intentionally contain already extracted fields. Visual segments give
 * extracted fields priority while residual fragments still select the original full
 * residual range, so accepted fields can be preserved during a scoped correction.
 */
export function buildMultiPassSourceHighlights(raw:string,preview:MultiPassSourcePreview):MultiPassSourceHighlightResult{
 const selections:MultiPassSourceSelection[]=[];
 for(const span of preview.spans){
  // Empty source values (for example RFC5424 user="" or an empty CSV cell)
  // are legitimate evidence but have no selectable source bytes.
  if(span.startByte===span.endByte)continue;
  const chars=fromSourceByteRange(raw,span.startByte,span.endByte);
  if(!chars)return {ok:false,reason:'INVALID_RANGE'};
  selections.push({kind:'field',path:span.path,startByte:span.startByte,endByte:span.endByte,
   text:raw.slice(chars[0],chars[1])});
 }
 for(const span of preview.residuals){
  const chars=fromSourceByteRange(raw,span.startByte,span.endByte);
  if(!chars)return {ok:false,reason:'INVALID_RANGE'};
  selections.push({kind:'residual',startByte:span.startByte,endByte:span.endByte,
   text:raw.slice(chars[0],chars[1])});
 }
 const boundaries=new Set<number>([0,new TextEncoder().encode(raw).byteLength]);
 for(const item of selections){boundaries.add(item.startByte);boundaries.add(item.endByte);}
 const ordered=[...boundaries].sort((a,b)=>a-b);
 const segments:MultiPassSourceSegment[]=[];
 for(let i=0;i<ordered.length-1;i++){
  const startByte=ordered[i]!,endByte=ordered[i+1]!;
  if(startByte===endByte)continue;
  const chars=fromSourceByteRange(raw,startByte,endByte);
  if(!chars)return {ok:false,reason:'INVALID_RANGE'};
  const text=raw.slice(chars[0],chars[1]);
  const fields=selections.filter(item=>item.kind==='field'&&item.startByte<=startByte&&item.endByte>=endByte);
  if(fields.length>1)return {ok:false,reason:'AMBIGUOUS_FIELD_OVERLAP'};
  if(fields.length===1){segments.push({kind:'field',text,selection:fields[0]!});continue;}
  const residuals=selections.filter(item=>item.kind==='residual'&&item.startByte<=startByte&&item.endByte>=endByte);
  if(residuals.length>1)return {ok:false,reason:'AMBIGUOUS_RESIDUAL_OVERLAP'};
  if(residuals.length===1){segments.push({kind:'residual',text,selection:residuals[0]!});continue;}
  segments.push({kind:'plain',text});
 }
 const merged:MultiPassSourceSegment[]=[];
 for(const segment of segments){
  const prior=merged.at(-1);
  if(prior&&prior.kind===segment.kind&&
    (prior.kind==='plain'||(segment.kind!=='plain'&&prior.selection===segment.selection))){
   prior.text+=segment.text;
  }else merged.push(segment);
 }
 if(merged.map(item=>item.text).join('')!==raw)
  return {ok:false,reason:'SOURCE_RECONSTRUCTION_FAILED'};
 return {ok:true,segments:merged,selectable:selections};
}
