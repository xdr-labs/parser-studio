/** Source-value scorer only: never certifies native or normalized mapping. */
export type Leaf = string|number|boolean|null;
export type FidelityCounts = {
  expected:number; extracted:number; exactValues:number; mismatchedValues:number;
  missingPaths:number; unexpectedPaths:number; exactStructure:boolean;
};
const unsafeKeys=new Set(['__proto__','constructor','prototype']);
const escapePart=(value:string)=>value.replaceAll('~','~0').replaceAll('/','~1');

export function jsonLeaves(value:unknown):Map<string,Leaf>{
  if(!value||typeof value!=='object'||Array.isArray(value))
    throw Error('JSON field scoring requires a source object');
  const leaves=new Map<string,Leaf>();
  function walk(node:unknown,pointer:string,depth:number):void{
    if(depth>24||leaves.size>4096)throw Error('Source exceeds bounded JSON field scoring');
    if(node&&typeof node==='object'){
      if(Array.isArray(node)){
        node.forEach((child,index)=>walk(child,pointer+'/'+index,depth+1));
      }else{
        for(const [key,child] of Object.entries(node)){
          if(unsafeKeys.has(key)||key.length>256)throw Error('Unsafe JSON key');
          walk(child,pointer+'/'+escapePart(key),depth+1);
        }
      }
      return;
    }
    if(node!==null&&!['string','number','boolean'].includes(typeof node))
      throw Error('Invalid JSON leaf');
    if(typeof node==='number'&&(!Number.isFinite(node)||
      (Number.isInteger(node)&&!Number.isSafeInteger(node))))
      throw Error('Unscoreable numeric field');
    leaves.set(pointer,node as Leaf);
  }
  walk(value,'',0);
  if(!leaves.size||leaves.size>4096)throw Error('Empty or oversized JSON leaf set');
  return leaves;
}

function sameStructure(a:unknown,b:unknown,depth=0):boolean{
  if(depth>24)return false;
  if(a===null||b===null||typeof a!=='object'||typeof b!=='object')
    return a===b&&typeof a===typeof b;
  if(Array.isArray(a)||Array.isArray(b))
    return Array.isArray(a)&&Array.isArray(b)&&a.length===b.length&&
      a.every((v,i)=>sameStructure(v,b[i],depth+1));
  const fields=Object.entries(a);
  return fields.length===Object.keys(b).length&&fields.every(([key,v])=>
    Object.hasOwn(b,key)&&sameStructure(v,(b as Record<string,unknown>)[key],depth+1));
}

/** Wrong values contribute a false positive AND a missed correct value. */
export function compareJsonValues(
  expected:Map<string,Leaf>,candidate:unknown,original:unknown,
):FidelityCounts{
  let extracted=new Map<string,Leaf>();
  try{extracted=jsonLeaves(candidate);}catch{/* Unsupported extraction: abstain. */}
  let exactValues=0,mismatchedValues=0,missingPaths=0,unexpectedPaths=0;
  for(const [path,value] of expected){
    if(!extracted.has(path))missingPaths++;
    else if(value===extracted.get(path)&&typeof value===typeof extracted.get(path))
      exactValues++;
    else mismatchedValues++;
  }
  for(const path of extracted.keys())if(!expected.has(path))unexpectedPaths++;
  return {expected:expected.size,extracted:extracted.size,exactValues,mismatchedValues,
    missingPaths,unexpectedPaths,
    exactStructure:extracted.size>0&&sameStructure(original,candidate)};
}
