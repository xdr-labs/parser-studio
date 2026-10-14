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
