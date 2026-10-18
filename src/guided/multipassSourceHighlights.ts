import type {MultiPassSourcePreview} from './multipassPreviewClient';

export type MultiPassSourceSelection={
 kind:'field'|'residual';startByte:number;endByte:number;path?:string;text:string;
};
export type MultiPassSourceSegment=
 | {kind:'plain';text:string}
 | {kind:'field'|'residual';text:string;selection:MultiPassSourceSelection};
export type MultiPassSourceHighlightResult=
 | {ok:true;segments:MultiPassSourceSegment[];selectable:MultiPassSourceSelection[]}
 | {ok:false;reason:'INVALID_RANGE'|'AMBIGUOUS_FIELD_OVERLAP'|'AMBIGUOUS_RESIDUAL_OVERLAP'|'SOURCE_RECONSTRUCTION_FAILED'};

function utf8Width(codePoint:number):number{
 if(codePoint<=0x7f)return 1;
 if(codePoint<=0x7ff)return 2;
 if(codePoint<=0xffff)return 3;
 return 4;
}
function utf8Boundaries(raw:string):{size:number;chars:Map<number,number>}{
 const chars=new Map<number,number>([[0,0]]);
 let byte=0,index=0;
 for(const symbol of raw){
  const code=symbol.codePointAt(0);
  if(code===undefined)continue;
  byte+=utf8Width(code);
  index+=symbol.length;
  chars.set(byte,index);
 }
 return {size:byte,chars};
}
function textAt(raw:string,chars:Map<number,number>,startByte:number,endByte:number):string|null{
 const start=chars.get(startByte),end=chars.get(endByte);
 if(start===undefined||end===undefined||start>end)return null;
 return raw.slice(start,end);
}
function overlaps(items:MultiPassSourceSelection[]):boolean{
 const sorted=[...items].sort((a,b)=>a.startByte-b.startByte||a.endByte-b.endByte);
 let end=-1;
 for(const item of sorted){
  if(item.startByte<end)return true;
  if(item.endByte>end)end=item.endByte;
 }
 return false;
}

/**
 * Build a lossless UTF-8-byte-aware source map from the trusted Multi-Pass preview.
 * A residual may intentionally contain already extracted fields. Visual segments give
 * extracted fields priority while residual fragments still select the original full
 * residual range, so accepted fields can be preserved during a scoped correction.
 *
 * The implementation deliberately builds the UTF-8/UTF-16 boundary table once and
 * sweeps non-overlapping field/residual intervals. This keeps large security JSON
 * previews bounded instead of repeatedly re-encoding the full source for every span.
 */
export function buildMultiPassSourceHighlights(raw:string,preview:MultiPassSourcePreview):MultiPassSourceHighlightResult{
 const boundary=utf8Boundaries(raw);
 const fields:MultiPassSourceSelection[]=[];
 const residuals:MultiPassSourceSelection[]=[];

 for(const span of preview.spans){
  // Empty source values are legitimate evidence but have no selectable bytes.
  if(span.startByte===span.endByte)continue;
  if(span.startByte<0||span.endByte>boundary.size||span.startByte>=span.endByte)
   return {ok:false,reason:'INVALID_RANGE'};
  const text=textAt(raw,boundary.chars,span.startByte,span.endByte);
  if(text===null)return {ok:false,reason:'INVALID_RANGE'};
  fields.push({kind:'field',path:span.path,startByte:span.startByte,endByte:span.endByte,text});
 }
 for(const span of preview.residuals){
  if(span.startByte<0||span.endByte>boundary.size||span.startByte>=span.endByte)
   return {ok:false,reason:'INVALID_RANGE'};
  const text=textAt(raw,boundary.chars,span.startByte,span.endByte);
  if(text===null)return {ok:false,reason:'INVALID_RANGE'};
  residuals.push({kind:'residual',startByte:span.startByte,endByte:span.endByte,text});
 }
 if(overlaps(fields))return {ok:false,reason:'AMBIGUOUS_FIELD_OVERLAP'};
 if(overlaps(residuals))return {ok:false,reason:'AMBIGUOUS_RESIDUAL_OVERLAP'};

 const selectable=[...fields,...residuals];
 const boundaries=new Set<number>([0,boundary.size]);
 for(const item of selectable){boundaries.add(item.startByte);boundaries.add(item.endByte);}
 const ordered=[...boundaries].sort((a,b)=>a-b);
 const fieldOrder=[...fields].sort((a,b)=>a.startByte-b.startByte||a.endByte-b.endByte);
 const residualOrder=[...residuals].sort((a,b)=>a.startByte-b.startByte||a.endByte-b.endByte);
 let fieldIndex=0,residualIndex=0;
 const segments:MultiPassSourceSegment[]=[];

 for(let i=0;i<ordered.length-1;i++){
  const startByte=ordered[i]!,endByte=ordered[i+1]!;
  if(startByte===endByte)continue;
  const text=textAt(raw,boundary.chars,startByte,endByte);
  if(text===null)return {ok:false,reason:'INVALID_RANGE'};

  while(fieldIndex<fieldOrder.length&&fieldOrder[fieldIndex]!.endByte<=startByte)fieldIndex++;
  const field=fieldOrder[fieldIndex];
  if(field&&field.startByte<=startByte&&field.endByte>=endByte){
   segments.push({kind:'field',text,selection:field});
   continue;
  }
  while(residualIndex<residualOrder.length&&residualOrder[residualIndex]!.endByte<=startByte)residualIndex++;
  const residual=residualOrder[residualIndex];
  if(residual&&residual.startByte<=startByte&&residual.endByte>=endByte){
   segments.push({kind:'residual',text,selection:residual});
   continue;
  }
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
 return {ok:true,segments:merged,selectable};
}
