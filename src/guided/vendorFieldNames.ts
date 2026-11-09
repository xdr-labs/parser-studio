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

/** Choose an original leaf key, or the unchanged source path if the leaf collides.
 * Never flatten dots to underscores or inject manufacturer/demo labels into a key.
 * The returned names are vendor-local; the native writer still owns its vendor object.
 */
export function vendorFieldNames(
  sources:readonly string[],occupied:readonly string[]=[]):ReadonlyMap<string,string>{
  const names=[...new Set(sources)].filter(safe);
  const counts=new Map<string,number>();
  for(const name of names){
    const leaf=name.split('.').at(-1)!;
    counts.set(leaf,(counts.get(leaf)??0)+1);
  }
  const used=[...occupied];
  const assigned=new Map<string,string>();
  const pending:string[]=[];
  // Give unambiguous short keys priority over fallback paths, regardless of
  // sample/event order. Sorting also prevents first-event-only naming changes.
  for(const name of names.slice().sort()){
    const leaf=name.split('.').at(-1)!;
    if(safe(leaf)&&counts.get(leaf)===1&&!used.some(x=>overlaps(x,leaf))){
      assigned.set(name,leaf);
      used.push(leaf);
    }else pending.push(name);
  }
  for(const name of pending){
    if(!used.some(x=>overlaps(x,name))){
      assigned.set(name,name);
      used.push(name);
    }
  }
  return assigned;
}

/** One-time cleanup for untouched legacy Auto Parser names only. Never rewrite
 * manual names, official Stellar mappings, or paths with ambiguous destinations.
 */
export function compactLegacyAutoVendorMappings(
  mappings:readonly MappingRule[],groups:Readonly<Record<string,FieldGroup>>,
):MappingRule[]{
  const generated=mappings.filter(mapping=>
    (groups[mapping.id]??'vendor_fields')==='vendor_fields'&&
    /^auto-(?:generic-)?\d+$/.test(mapping.id)&&
    (mapping.target===mapping.source.replace(/\./g,'_')||mapping.target===mapping.source));
  if(!generated.length)return mappings as MappingRule[];
  const selected=new Set(generated.map(item=>item.id));
  const occupied=mappings.filter(item=>!selected.has(item.id)).map(item=>item.target);
  const names=vendorFieldNames(generated.map(item=>item.source),occupied);
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
