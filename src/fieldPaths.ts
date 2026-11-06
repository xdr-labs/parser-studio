/**
 * Browser-local conservative, bounded projection of ParserProject 0.1 dotted
 * source paths. Backend lookup prefers an exact literal key before descending
 * nested JSON objects. Never traverse inherited/prototype or array-index paths.
 */
import type {MappingWhen} from './model';

const PATH = /^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_DEPTH = 8;
const MAX_FIELDS = 100;

export function safeLocalFieldPath(path: string): boolean {
  return path.length > 0 && path.length <= 128 &&
    (PATH.test(path)||path==='@timestamp') &&
    path.split('.').every((segment) => !UNSAFE.has(segment));
}

function objectRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function lookupFieldValue(
  fields: Record<string, unknown>, path: string,
  kind?: 'literal_root' | 'nested',
): { found: true; value: unknown } | { found: false } {
  if (!safeLocalFieldPath(path) || path.split('.').length > MAX_DEPTH) return { found: false };
  // A reviewed JSONata selector preserves whether it selected the literal
  // root key `a.b` or nested a -> b. Legacy mappings stay flexible.
  if(kind==='literal_root'){
    return Object.prototype.hasOwnProperty.call(fields,path)
      ?{found:true,value:fields[path]}:{found:false};
  }
  if (kind!=='nested' && Object.prototype.hasOwnProperty.call(fields, path)) {
    return { found: true, value: fields[path] };
  }
  let value: unknown = fields;
  for (const segment of path.split('.')) {
    if (!objectRecord(value) || !Object.prototype.hasOwnProperty.call(value, segment)) {
      return { found: false };
    }
    value = value[segment];
  }
  return { found: true, value };
}

/** Detect a source path with multiple JSON interpretations (flat dotted keys
 * versus nested objects, including mixed segment boundaries). Native Ruby
 * rejects the same collision at run time.
 */
export function hasAmbiguousFieldPath(fields:Record<string,unknown>,path:string):boolean{
  if(!safeLocalFieldPath(path))return false;
  const segments=path.split('.');
  if(segments.length<2||segments.length>MAX_DEPTH)return false;
  let matches=0;
  const visit=(node:unknown,at:number):void=>{
    if(!objectRecord(node)||matches>1)return;
    for(let end=at+1;end<=segments.length;end++){
      const name=segments.slice(at,end).join('.');
      if(!Object.prototype.hasOwnProperty.call(node,name))continue;
      if(end===segments.length)matches++;
      else visit(node[name],end);
      if(matches>1)return;
    }
  };
  visit(fields,0);
  return matches>1;
}

/** Returns safe leaf *names* only, default 100; 101 is a truncation sentinel for strict callers. */
export function listSafeLeafPaths(
  fields: Record<string, unknown>, limit: 100 | 101 = MAX_FIELDS,
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
        if (prefix && key.includes('.')) continue;
        if (!safeLocalFieldPath(next)) continue;
        visit(value[key], next, depth + 1);
      }
    } else if (prefix && value !== null && !Array.isArray(value) && !seen.has(prefix)) {
      seen.add(prefix);
      results.push(prefix);
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
        if((path && key.includes('.')) || !safeLocalFieldPath(next)){
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
