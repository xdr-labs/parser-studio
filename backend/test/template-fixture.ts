import {readFileSync} from 'node:fs';
/** Resolve the actual compiler-owned operator source for standalone extraction probes. */
export function resolvedTemplate(name:string):string{
 const source=readFileSync(new URL('../templates/'+name,import.meta.url),'utf8');
 const marker='# __PARSERSTUDIO_CANONICAL_OPERATORS__';
 if(source.split(marker).length!==2)throw new Error('Canonical operator marker must occur exactly once');
 return source.replace(marker,readFileSync(new URL('../templates/canonical-operators.rb.tpl',import.meta.url),'utf8'));
}
