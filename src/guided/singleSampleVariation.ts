/** Local, bounded metamorphic probe for a single source log. Synthetic
 * substitutions are NOT independent holdout events or vendor ground truth.
 * Never save a mutation as a new user log or send it to an LLM.
 */
import type {SuiteResult,ParserDraft} from '../model';

export interface SingleSampleVariation {
  originalSource:string;
  mutatedSource:string;
  previousValue:string;
  replacementValue:string;
}
export function buildSingleSampleVariation(
  source:string,format:ParserDraft['format'],
):SingleSampleVariation|null{
  if(!['csv','kv','regex'].includes(format)||!source||
     source.length>4096||/[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]/.test(source))
    return null;
  const ip=/\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  for(const found of source.matchAll(ip)){
    const old=found[0],pos=found.index,end=pos+old.length;
    if((pos&&/[A-Za-z0-9_.]/.test(source[pos-1]!))||
      (end<source.length&&/[A-Za-z0-9_.]/.test(source[end]!)))
      continue;
    const nums=old.split('.').map(Number);
    if(nums.some(n=>!Number.isInteger(n)||n>255)||old.split('.').some(n=>
      n.length>1&&n.startsWith('0')))continue;
    const replacement=old==='203.0.113.77'?'198.51.100.77':'203.0.113.77';
    return {originalSource:source,
      mutatedSource:source.slice(0,pos)+replacement+source.slice(end),
      previousValue:old,replacementValue:replacement};
  }
  return null;
}
function leaves(node:unknown,prefix='',depth=0,out=new Map<string,unknown>()):Map<string,unknown>{
  if(depth>12||out.size>256)return out;
  if(node&&typeof node==='object'){
    if(Array.isArray(node)){
      node.slice(0,128).forEach((v,i)=>leaves(v,prefix+'['+i+']',depth+1,out));
    }else{
      Object.entries(node).slice(0,128).forEach(([k,v])=>{
        if(k==='__proto__'||k==='constructor'||k==='prototype')return;
        leaves(v,prefix?prefix+'.'+k:k,depth+1,out);
      });
    }
  }else if(prefix)out.set(prefix,node);
  return out;
}
/** Only identical extraction paths carrying the substituted value qualify. */
export function verifySingleSampleVariation(
  variation:SingleSampleVariation,original:SuiteResult,mutated:SuiteResult,
):boolean{
  if(original.engine!=='browser-preview'||mutated.engine!=='browser-preview'||
    original.counts.total!==1||mutated.counts.total!==1||
    original.events[0]?.raw!==variation.originalSource||
    mutated.events[0]?.raw!==variation.mutatedSource||
    original.events[0]?.status!=='pass'||mutated.events[0]?.status!=='pass'||
    !original.events[0].extracted||!mutated.events[0].extracted||
    !original.events[0].normalizedOk||!mutated.events[0].normalizedOk)
    return false;
  const before=leaves(original.events[0].fields);
  const after=leaves(mutated.events[0].fields);
  return [...before].some(([path,val])=>val===variation.previousValue&&
    after.get(path)===variation.replacementValue);
}
