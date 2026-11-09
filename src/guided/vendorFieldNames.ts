import type {MappingRule} from '../model';
import type {FieldGroup} from './contract';

const SAFE_FIELD=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const UNSAFE_SEGMENTS=new Set(['__proto__','prototype','constructor']);
const RESERVED_ROOTS=new Set(['msg_origin','stellar_log_index','parser_err_msg',
  'parser_err_stage','parser_err_field','parserstudio_source','parserstudio_transport',
  'parserstudio_event_family']);

const safe=(name:string):boolean=>SAFE_FIELD.test(name)&&
  name.split('.').every(part=>part.length>0&&!UNSAFE_SEGMENTS.has(part))&&
  !RESERVED_ROOTS.has(name.split('.')[0]!);
const overlaps=(a:string,b:string):boolean=>
  a===b||a.startsWith(b+'.')||b.startsWith(a+'.');

/**
 * Every safe source has exactly two candidates: its unchanged full path and
 * its unchanged final segment. Choosing one may conflict with another source.
 * This is a 2-SAT feasibility problem, not a greedy name-replacement pass.
 * Preserve ALL source identities, or explicitly return unresolved sources.
 */
export interface VendorFieldNamePlan {
  names:ReadonlyMap<string,string>;
  unresolved:readonly string[];
}

export function planVendorFieldNames(
  sources:readonly string[],occupied:readonly string[]=[]):VendorFieldNamePlan{
  const inputs=[...new Set(sources)].filter(safe).sort();
  const n=inputs.length;
  if(n>256)return {names:new Map(),unresolved:inputs};
  const candidates=inputs.map(source=>[source,source.split('.').at(-1)!] as const);
  const leafCounts=new Map<string,number>();
  for(const [,leaf] of candidates)leafCounts.set(leaf,(leafCounts.get(leaf)??0)+1);
  const edges:Array<number[]> = Array.from({length:2*n},()=>[]);
  const reverse:Array<number[]> = Array.from({length:2*n},()=>[]);
  const imply=(from:number,to:number)=>{
    edges[from]!.push(to);reverse[to]!.push(from);
  };
  const forbid=(id:number,mode:0|1)=>imply(2*id+mode,2*id+(mode^1));
  for(let i=0;i<n;i++){
    for(let mode=0 as 0|1;mode<=1;mode=(mode+1) as 0|1){
      if(occupied.some(other=>overlaps(candidates[i]![mode],other)))forbid(i,mode);
    }
  }
  for(let i=0;i<n;i++)for(let j=i+1;j<n;j++){
    for(let a=0 as 0|1;a<=1;a=(a+1) as 0|1)
      for(let b=0 as 0|1;b<=1;b=(b+1) as 0|1){
        if(!overlaps(candidates[i]![a],candidates[j]![b]))continue;
        // Neither conflicting choice may be true simultaneously.
        imply(2*i+a,2*j+(b^1));
        imply(2*j+b,2*i+(a^1));
      }
  }
  // SCC determines satisfiability; fixed decisions prefer leaf names where
  // feasible, independent of sample order. No per-source exception or suffix.
  function solve(forced:Int8Array,strictDuplicateLeaves:boolean):Int8Array|null{
    const extra:Array<number[]> = Array.from({length:2*n},()=>[]);
    const extraReverse:Array<number[]> = Array.from({length:2*n},()=>[]);
    for(let i=0;i<n;i++){
      // Strict duplicate constraints are independent of preference decisions.
      // Choosing a conflicting leaf makes this feasibility attempt UNSAT.
      if(strictDuplicateLeaves&&leafCounts.get(candidates[i]![1])!>1){
        extra[2*i+1]!.push(2*i);extraReverse[2*i]!.push(2*i+1);
      }
      if(forced[i]===-1)continue;
      const from=2*i+(forced[i]===1?0:1),to=from^1;
      extra[from]!.push(to);extraReverse[to]!.push(from);
    }
    const seen=new Uint8Array(2*n),order:number[]=[];
    function walk(v:number):void{
      seen[v]=1;
      for(const to of edges[v]!)if(!seen[to])walk(to);
      for(const to of extra[v]!)if(!seen[to])walk(to);
      order.push(v);
    }
    for(let v=0;v<2*n;v++)if(!seen[v])walk(v);
    const component=new Int32Array(2*n).fill(-1);
    function collect(v:number,c:number):void{
      component[v]=c;
      for(const from of reverse[v]!)if(component[from]===-1)collect(from,c);
      for(const from of extraReverse[v]!)if(component[from]===-1)collect(from,c);
    }
    let count=0;
    for(let k=order.length-1;k>=0;k--){
      const v=order[k]!;
      if(component[v]===-1)collect(v,count++);
    }
    const result=new Int8Array(n);
    for(let i=0;i<n;i++){
      if(component[2*i]===component[2*i+1])return null;
      result[i]=component[2*i+1]!>component[2*i]!?1:0;
    }
    return result;
  }
  const choices=new Int8Array(n).fill(-1);
  let strict=true;
  let result=solve(choices,strict);
  if(!result){strict=false;result=solve(choices,strict);}
  if(!result)return {names:new Map(),unresolved:inputs};
  if(n<=128){
    for(let i=0;i<n;i++){
      choices[i]=1;
      const preferred=solve(choices,strict);
      if(preferred){result=preferred;continue;}
      choices[i]=0;
      result=solve(choices,strict)!;
    }
  }else{
    // Bounded large-source mode: the valid SCC solution remains lossless,
    // and simple leaf upgrades never compromise another assigned full path.
    for(let i=0;i<n;i++){
      if(result[i]===1)continue;
      const leaf=candidates[i]![1];
      // The large (>128) fast path must preserve the same duplicate-leaf
      // identity policy as the exact solver. When strict placement succeeds,
      // duplicate last segments retain their full original source paths.
      if(strict&&leafCounts.get(leaf)!>1)continue;
      if(occupied.some(x=>overlaps(x,leaf)))continue;
      if(candidates.some((choice,j)=>j!==i&&overlaps(leaf,choice[result![j]!])))continue;
      result[i]=1;
    }
  }
  const names=new Map<string,string>();
  for(let i=0;i<n;i++)names.set(inputs[i]!,candidates[i]![result[i]!]!);
  return {names,unresolved:[]};
}

/** Return a complete allocation, or an empty map instead of silently dropping
 * any source path. Callers must treat a missing allocation as REVIEW_REQUIRED. */
export function vendorFieldNames(
  sources:readonly string[],occupied:readonly string[]=[]):ReadonlyMap<string,string>{
  return planVendorFieldNames(sources,occupied).names;
}

/** Only trusted auto-generated rules may be upgraded. Legacy unmarked rules
 * are not verifiably untouched and must remain unchanged until user approval. */
export function compactLegacyAutoVendorMappings(
  mappings:readonly MappingRule[],groups:Readonly<Record<string,FieldGroup>>,
):MappingRule[]{
  const generated=mappings.filter(mapping=>
    mapping.authoring?.origin==='AUTO'&&
    (groups[mapping.id]??'vendor_fields')==='vendor_fields'&&
    (mapping.target===mapping.source.replace(/\./g,'_')||mapping.target===mapping.source));
  if(!generated.length)return mappings as MappingRule[];
  const selected=new Set(generated.map(item=>item.id));
  const occupied=mappings.filter(item=>!selected.has(item.id)).map(item=>item.target);
  const names=vendorFieldNames(generated.map(item=>item.source),occupied);
  if(names.size!==generated.length)return mappings as MappingRule[];
  let changed=false;
  const updated=mappings.map(mapping=>{
    if(!selected.has(mapping.id))return mapping;
    const target=names.get(mapping.source);
    if(!target||target===mapping.target)return mapping;
    changed=true;
    return {...mapping,target};
  });
  return changed?updated:mappings as MappingRule[];
}
