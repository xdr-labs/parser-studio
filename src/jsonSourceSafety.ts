/** Native Ruby JSON source contract: 8 nested levels and valid UTF-16 pairs.
 * This is source validation, not the generic project-JSON authorization check. */
export function jsonSourceValueValid(value:unknown,maxDepth=8):boolean{
  const pairs=(s:string):boolean=>{
    for(let i=0;i<s.length;i++){
      const unit=s.charCodeAt(i);
      if(unit>=0xD800&&unit<=0xDBFF){
        const next=i+1<s.length?s.charCodeAt(++i):-1;
        if(next<0xDC00||next>0xDFFF)return false;
      }else if(unit>=0xDC00&&unit<=0xDFFF)return false;
    }
    return true;
  };
  const pending:Array<{value:unknown;depth:number}>=[{value,depth:0}];
  while(pending.length){
    const current=pending.pop()!;
    if(current.depth>maxDepth)return false;
    if(typeof current.value==='string'&&!pairs(current.value))return false;
    if(current.value!==null&&typeof current.value==='object'){
      for(const [key,entry] of Object.entries(current.value)){
        if(!pairs(key))return false;
        pending.push({value:entry,depth:current.depth+1});
      }
    }
  }
  return true;
}
