/** Ensure that JSON escapes cannot silently turn lone UTF-16 surrogates
 * into UTF-8 replacement characters when records or parser pairs are encoded.
 */
export function hasOnlyPairedSurrogates(text:string):boolean {
  for(let index=0;index<text.length;index++){
    const current=text.charCodeAt(index);
    if(current>=0xD800 && current<=0xDBFF){
      const next=index+1<text.length?text.charCodeAt(index+1):-1;
      if(next<0xDC00 || next>0xDFFF)return false;
      index++;
    }else if(current>=0xDC00 && current<=0xDFFF)return false;
  }
  return true;
}

/** Iterative traversal of JSON strings and object keys (no Ruby execution). */
export function hasValidUnicodeJson(value:unknown):boolean {
  const pending:unknown[]=[value];
  while(pending.length){
    const current=pending.pop();
    if(typeof current==="string"){
      if(!hasOnlyPairedSurrogates(current))return false;
    }else if(current!==null && typeof current==="object"){
      for(const [key,part] of Object.entries(current)){
        if(!hasOnlyPairedSurrogates(key))return false;
        pending.push(part);
      }
    }
  }
  return true;
}
