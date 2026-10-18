/**
 * Source character -> original UTF-8 byte boundaries in linear time.
 * Returns null for unpaired UTF-16 surrogates rather than fabricating
 * replacement-byte offsets. Source callers enforce their own size caps.
 */
export function utf8OriginalByteOffsets(source:string):Uint32Array|null{
  const offsets=new Uint32Array(source.length+1);
  let count=0;
  for(let pos=0;pos<source.length;pos++){
    const ch=source.charCodeAt(pos);
    if(ch>=0xd800&&ch<=0xdbff){
      const next=source.charCodeAt(pos+1);
      if(!(next>=0xdc00&&next<=0xdfff))return null;
      offsets[pos+1]=count; // A surrogate midpoint is not a token boundary.
      count+=4;pos++;
      offsets[pos+1]=count;
    }else{
      if(ch>=0xdc00&&ch<=0xdfff)return null;
      count+=ch<=0x7f?1:ch<=0x7ff?2:3;
      offsets[pos+1]=count;
    }
  }
  return offsets;
}
