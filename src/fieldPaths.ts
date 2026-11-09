/**
 * Browser-local conservative, bounded projection of ParserProject 0.1 dotted
 * source paths. All possible literal/nested partitions are considered.
 * Multiple matches fail closed; inherited and array-index paths are excluded.
 */
import type {MappingWhen} from './model';
import {resolveCanonicalSourcePath,validCanonicalSourcePath} from '../backend/src/canonical-operator-contract';

const MAX_DEPTH = 8;
const MAX_FIELDS = 100;

export function safeLocalFieldPath(path: string): boolean {
  return validCanonicalSourcePath(path);
}

function objectRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function lookupFieldValue(
  fields: Record<string, unknown>, path: string,
  kind?: 'literal_root' | 'nested',
): { found: true; value: unknown } | { found: false } {
  const resolved=resolveCanonicalSourcePath(fields,path,kind);
  return resolved.status==='unique'
    ?{found:true,value:resolved.value}:{found:false};
}

export function hasAmbiguousFieldPath(fields:Record<string,unknown>,path:string):boolean{
  return resolveCanonicalSourcePath(fields,path).status==='ambiguous';
}

/** Scan actual source leaves rather than only eligible suggestions. Ambiguous
 * paths must not disappear silently when candidate filtering excludes them.
 * Return a conservative failure if the bounded scan cannot finish.
 */
export function hasAmbiguousSourceFields(fields:Record<string,unknown>):boolean{
  let visits=0;
  const visit=(value:unknown,path:string,depth:number):boolean=>{
    if(++visits>1024)return true;
    if(path&&!safeLocalFieldPath(path))return false;
    if(!objectRecord(value))return Boolean(path&&hasAmbiguousFieldPath(fields,path));
    if(depth>=MAX_DEPTH)return false;
    for(const [key,child] of Object.entries(value)){
      if(visit(child,path?path+'.'+key:key,depth+1))return true;
    }
    return false;
  };
  return visit(fields,'',0);
}

export function listSafeLeafPaths(
  // 1025 is reserved for exhaustive official-candidate reconnaissance
  // (1024 safe paths plus a fail-closed overflow sentinel). Authoring
  // remains capped at its existing 100/101 paths.
  fields: Record<string, unknown>, limit: 100 | 101 | 1025 = MAX_FIELDS,
): string[] {
  const results: string[] = [];
  const seen = new Set<string>();
  const visit = (value: unknown, prefix: string, depth: number) => {
    if (results.length >= limit || depth > MAX_DEPTH || (prefix && !safeLocalFieldPath(prefix))) return;
    if (objectRecord(value)) {
      if (depth === MAX_DEPTH) return;
      for (const key of Object.keys(value)) {
        if (results.length >= limit) break;
        const next = prefix ? prefix + '.' + key : key;
        if (!safeLocalFieldPath(next)) continue;
        visit(value[key], next, depth + 1);
      }
    } else if (prefix && value !== null && !Array.isArray(value) && !seen.has(prefix)) {
      const resolved=lookupFieldValue(fields,prefix);
      if(resolved.found && Object.is(resolved.value,value)){
        seen.add(prefix);
        results.push(prefix);
      }
    }
  };
  visit(fields, '', 0);
  return results;
}

/** Number of source values that cannot be mapped with the bounded parser schema.
 * The preview may preserve such data, but it must never report it as mapped. */
export function countUnaddressableSourceValues(fields:Record<string,unknown>):number {
  const addressable=new Set(listSafeLeafPaths(fields));
  const resolvedPaths=new Set<string>();
  let missing=0;
  const visit=(value:unknown,path:string,depth:number):void=>{
    if(Array.isArray(value)){missing++;return;}
    if(objectRecord(value)){
      if(depth>=MAX_DEPTH){missing++;return;}
      for(const [key,child] of Object.entries(value)){
        const next=path?path+'.'+key:key;
        if(!safeLocalFieldPath(next)){
          missing++;continue;
        }
        visit(child,next,depth+1);
      }
    }else if(path){
      const resolved=lookupFieldValue(fields,path);
      if(value===null||!addressable.has(path)||!resolved.found||
         !Object.is(resolved.value,value)||resolvedPaths.has(path))missing++;
      else resolvedPaths.add(path);
    }
  };
  visit(fields,'',0);
  return missing;
}

/** Only bounded exact-value predicates are compilable into both browser and native Ruby. */
export function validMappingWhen(when:unknown):when is MappingWhen{
  if(!when||typeof when!=='object'||Array.isArray(when))return false;
  const rule=when as Record<string,unknown>;
  return Object.keys(rule).length===3&&
    Object.keys(rule).every(key=>['sourcePath','operator','values'].includes(key))&&
    typeof rule.sourcePath==='string'&&safeLocalFieldPath(rule.sourcePath)&&
    rule.sourcePath.split('.').length<=8&&rule.operator==='in'&&
    Array.isArray(rule.values)&&rule.values.length>=1&&rule.values.length<=16&&
    rule.values.every(value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,32}$/.test(value))&&
    new Set(rule.values).size===rule.values.length;
}
export function mappingWhenApplies(fields:Record<string,unknown>,when?:MappingWhen):boolean{
  if(!when)return true;
  if(!validMappingWhen(when))return false;
  // An event with both a literal dotted key and a nested path cannot prove
  // which value controls semantic eligibility. Skip this field, not the log.
  if(hasAmbiguousFieldPath(fields,when.sourcePath))return false;
  const found=lookupFieldValue(fields,when.sourcePath);
  return found.found&&found.value!==null&&found.value!==undefined&&
    (typeof found.value==='string'||typeof found.value==='number')&&
    when.values.includes(String(found.value));
}
