/** A bounded source preview may only expose offsets on complete UTF-8 code
 * points. TextEncoder guarantees valid UTF-8; continuation bytes (10xxxxxx)
 * must not be selected as the start/end of an extracted or residual span.
 */
export function isUtf8ByteBoundary(bytes:Uint8Array,offset:number):boolean{
 return Number.isSafeInteger(offset)&&offset>=0&&offset<=bytes.byteLength&&
  (offset===0||offset===bytes.byteLength||(bytes[offset]!&0xc0)!==0x80);
}

/** Convert UTF-16 browser selection indices into UTF-8 source byte positions. */
export interface SourceByteRange {startByte:number;endByte:number;text:string}
export function toSourceByteRange(raw:string,start:number,end:number):SourceByteRange|null{
 if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||end>raw.length||start>=end)return null;
 const isSplit=(i:number)=>i>0&&i<raw.length&&
  /[\uD800-\uDBFF]/.test(raw[i-1]!)&&/[\uDC00-\uDFFF]/.test(raw[i]!);
 if(isSplit(start)||isSplit(end))return null;
 const encoder=new TextEncoder();
 return {startByte:encoder.encode(raw.slice(0,start)).byteLength,
  endByte:encoder.encode(raw.slice(0,end)).byteLength,text:raw.slice(start,end)};
}
/** Reverse a trusted engine UTF-8 byte span into browser UTF-16 indices. */
export function fromSourceByteRange(raw:string,startByte:number,endByte:number):[number,number]|null{
 const bytes=new TextEncoder().encode(raw);
 if(!Number.isSafeInteger(startByte)||!Number.isSafeInteger(endByte)||
  startByte<0||startByte>=endByte||endByte>bytes.length)return null;
 const prefix=new TextDecoder('utf-8',{fatal:true});
 try{
  const start=prefix.decode(bytes.slice(0,startByte)).length;
  const end=prefix.decode(bytes.slice(0,endByte)).length;
  if(toSourceByteRange(raw,start,end)?.startByte!==startByte||
     toSourceByteRange(raw,start,end)?.endByte!==endByte)return null;
  return [start,end];
 }catch{return null;}
}
