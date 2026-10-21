/** Detect duplicate decoded member names within each JSON object scope.
 *
 * Call only after JSON.parse has validated the complete input. A strict
 * scanner is needed because JSON.parse silently overwrites earlier members.
 * It operates on the original source string and never emits key/value data.
 * Object scopes are distinct; separate array elements may reuse names.
 */
export function hasDuplicateJsonObjectKeys(source:string):boolean{
  const stack:Array<Set<string>|null>=[];
  for(let index=0;index<source.length;index++){
    const char=source.charCodeAt(index);
    if(char===123){stack.push(new Set<string>());continue;} // {
    if(char===91){stack.push(null);continue;}               // [
    if(char===125||char===93){stack.pop();continue;}         // } ]
    if(char!==34)continue;                                   // "
    const start=index;
    index++;
    while(index<source.length){
      const byte=source.charCodeAt(index);
      if(byte===92){index+=2;continue;} // escaped code unit
      if(byte===34)break;
      index++;
    }
    const end=index+1;
    const scope=stack[stack.length-1];
    if(!scope)continue;
    let lookahead=end;
    while(lookahead<source.length&&[9,10,13,32].includes(source.charCodeAt(lookahead)))
      lookahead++;
    if(source.charCodeAt(lookahead)!==58)continue; // member-name colon
    const name=JSON.parse(source.slice(start,end)) as string;
    if(scope.has(name))return true;
    scope.add(name);
  }
  return false;
}
