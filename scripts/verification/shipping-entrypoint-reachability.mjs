/**
 * Close the historical-only code audit escape route. A source file with a
 * handler is not a product API unless reachable from the shipping entrypoint.
 *
 * This is a source-import graph check, not a dynamic-execution proof.
 * Runtime HTTP/404 behavior is separately checked by the actual E2E suite.
 */
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import path from 'node:path';
const model=JSON.parse(readFileSync('contracts/shipping-surface.v1.json','utf8'));
assert.equal(model.contract,'parser-studio.shipping-surface.v1');
assert.equal(model.sourceMode,'STATIC_REACHABILITY_NOT_DYNAMIC_COVERAGE');
assert.ok(existsSync(model.webEntrypoint));
assert.ok(existsSync(model.backendEntrypoint));
assert.ok(existsSync(model.legacyOnlyHttp.module));
const root=process.cwd();
const normalize=(name)=>path.relative(root,path.resolve(root,name)).replaceAll('\\','/');
const backendPath=(name)=>normalize(name).startsWith('backend/src/');
const importPattern=/\b(?:import|export)\s+(?:type\s+)?(?:[^"'\n]*?\s+from\s+)?["'](\.[^"'\n]+)["']|\bimport\s*\(\s*["'](\.[^"'\n]+)["']\s*\)/g;

function importsOf(source,read){
  const content=read(source);
  const found=[];
  for(const hit of content.matchAll(importPattern)){
    const name=hit[1]||hit[2];
    if(!name)continue;
    let candidate=path.resolve(root,path.dirname(source),name);
    if(candidate.endsWith('.js'))candidate=candidate.slice(0,-3)+'.ts';
    else if(candidate.endsWith('.mjs'))candidate=candidate.slice(0,-4)+'.mts';
    const relative=normalize(candidate);
    if(backendPath(relative)&&existsSync(relative))found.push(relative);
  }
  return found;
}
function transitivelyReachable(entry,read){
  const visited=new Set();
  const todo=[entry];
  while(todo.length){
    const node=todo.pop();
    if(!node||visited.has(node))continue;
    visited.add(node);
    for(const dependency of importsOf(node,read)){
      if(!visited.has(dependency))todo.push(dependency);
    }
  }
  return visited;
}
const read=(name)=>readFileSync(name,'utf8');
const reached=transitivelyReachable(model.backendEntrypoint,read);
for(const name of model.backendRequired){
  assert.ok(reached.has(name),'missing actual backend import route: '+name);
}
for(const name of model.backendUnreachable){
  assert.ok(!reached.has(name),'historical/unsafe backend module reached shipping API: '+name);
}
const src=model.backendEntrypoint;
const injected=transitivelyReachable(src,name=>
  read(name)+(name===src?"\nimport './http.js';\n":''));
assert.ok(injected.has(model.legacyOnlyHttp.module),
  'test must catch a future accidental legacy-HTTP exposure');
assert.ok(!reached.has(model.legacyOnlyHttp.module));
assert.equal(model.legacyOnlyHttp.mainlineReachable,false);
assert.equal(model.nativeTargetVerified,false);
console.log('SHIPPING_ENTRYPOINT_REACHABILITY_PASS backend_modules='+reached.size+
  ' legacy_http_unreachable=true synthetic_import_mutation_detected=true');
