import {coerceCanonicalValue} from '../backend/src/canonical-value-contract';
import {canonicalIgnoreSourceValue} from '../backend/src/canonical-operator-contract';

/**
 * Unmapped source fields (Owner decision Q3-1, 2026-11-24): every field the reader extracted is kept. A field no
 * mapping reads - also one the sample never showed - is written into the vendor namespace at its original path
 * (body.city -> <vendor>.body.city), so the same source keeps the same name in every event and no two sources
 * share one. Only where that path is a vendor field a mapping writes (body.user mapped as vendor "user", and a root
 * user at run time), or where a key itself contains a dot, the field goes under the reserved parserstudio_unmapped
 * object at its original path. A value is kept as its text: a string unchanged, a number, boolean, array or object
 * as the canonical string mapping renders it (the generated Ruby renders the same text). Values the mapping
 * contract treats as missing (null, the ignored values and blank strings) are not written, as for mapped fields.
 * Generic Structural parsers keep every field in parserstudio_source and are not changed.
 * The generated Ruby implements the same rule (backend/templates/canonical-operators.rb.tpl,
 * parserstudio_preserve_unmapped).
 */
export const UNMAPPED_COLLISION_ROOT='parserstudio_unmapped';
export const UNMAPPED_IGNORED_VALUES:readonly string[]=['','N/A','-'];

/** An enrichment output the kept fields own: the vendor namespace's parserstudio_unmapped object, and, while fields
 * are kept, the bare manufacturer name, which is then the vendor namespace (independent audit of 2b6602c, G-2/G-4). */
export function reservedForUnmapped(target:string,vendor:string,keepsUnmapped:boolean):boolean{
  const own=vendor+'.'+UNMAPPED_COLLISION_ROOT;
  return target===own||target.startsWith(own+'.')||(keepsUnmapped&&target===vendor);
}

/** kind: the mapping's sourcePathKind ('literal_root', 'nested', or undefined for the default lookup). */
export interface CoveredSource{source:string;literal:boolean;nestedOnly?:boolean}
export interface UnmappedLeaf{path:string[];value:unknown}

const plainObject=(value:unknown):value is Record<string,unknown>=>
  value!==null&&typeof value==='object'&&!Array.isArray(value);

/** Leaves of the extracted fields that no applied mapping source is, or contains. Non-empty objects are walked;
 * arrays, empty objects and scalars are leaves. */
export function unmappedLeaves(fields:Record<string,unknown>,covered:readonly CoveredSource[]):UnmappedLeaf[]{
  const prefixes=covered.map(item=>item.literal?[item.source]:item.source.split('.'));
  // A source of the default path kind also reads a literal key spelled the same ("policy.id"), as lookupFieldValue
  // does; a 'nested' source does not (final audit F-2: {"m.n":"10"} beside a nested m.n mapping was lost).
  const names=new Set(covered.filter(item=>!item.literal&&!item.nestedOnly).map(item=>item.source));
  const leaves:UnmappedLeaf[]=[];
  const walk=(value:unknown,path:string[])=>{
    if(path.length&&(names.has(path.join('.'))||
      prefixes.some(prefix=>prefix.length<=path.length&&prefix.every((part,i)=>part===path[i]))))return;
    if(plainObject(value)&&Object.keys(value).length>0){
      for(const key of Object.keys(value))walk(value[key],[...path,key]);
      return;
    }
    if(path.length)leaves.push({path,value});
  };
  walk(fields,[]);
  return leaves;
}

/** The text an unmapped value is kept as, or undefined when the value is missing by the mapping contract. */
export function unmappedText(value:unknown):string|undefined|Error{
  if(canonicalIgnoreSourceValue(value,UNMAPPED_IGNORED_VALUES))return undefined;
  if(typeof value==='string')return value;
  const converted=coerceCanonicalValue(value,'string');
  return converted.error?new Error(converted.error):String(converted.value);
}

/** A vendor output name a mapping (source) or an enrichment (no source) writes. */
export interface ReservedName{target:string;source?:string}
/** Where an unmapped leaf is written inside the vendor namespace. A name another family's mapping writes from the
 * same source is that source's name, not a clash: the field keeps one name in every event. */
export function unmappedOutputPath(path:readonly string[],occupied:readonly ReservedName[]):string[]{
  const name=path.join('.');
  const clash=path.some(part=>part.includes('.'))||path[0]===UNMAPPED_COLLISION_ROOT||
    occupied.some(({target,source})=>!(target===name&&source===name)&&
      (target===name||target.startsWith(name+'.')||name.startsWith(target+'.')));
  return clash?[UNMAPPED_COLLISION_ROOT,...path]:[...path];
}

const ownHas=(record:Record<string,unknown>,key:string)=>Object.prototype.hasOwnProperty.call(record,key);
const ownSet=(record:Record<string,unknown>,key:string,value:unknown)=>
  Object.defineProperty(record,key,{value,enumerable:true,writable:true,configurable:true});

/** Writes value at path; false when a part of the path already holds something else (nothing is overwritten). */
export function assignUnmapped(container:Record<string,unknown>,path:readonly string[],value:string):boolean{
  let current=container;
  for(const part of path.slice(0,-1)){
    if(!ownHas(current,part))ownSet(current,part,{});
    const child=current[part];
    if(!plainObject(child))return false;
    current=child;
  }
  const last=path[path.length-1]!;
  if(ownHas(current,last))return false;
  ownSet(current,last,value);
  return true;
}
