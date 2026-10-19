import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';
function project(){
 const p=sampleProject();p.projectId='draft-mixed_demo';p.slug='mixed_demo';
 p.extraction={format:'mixed',mixedFormats:['json','kv','cef','leef']};
 p.normalization.topFields={
  'src_ip':{normalized_name:'srcip',data_type:'ip'},
  'dst_port':{normalized_name:'dstport',data_type:'port'},
  action:{normalized_name:'action',data_type:'string'},
  src:{normalized_name:'cef_src',data_type:'ip'},
  dpt:{normalized_name:'cef_port',data_type:'port'},
  act:{normalized_name:'cef_action',data_type:'string'},
  dstPort:{normalized_name:'leef_port',data_type:'port'},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[
  {field:'action',operator:'equals',value:'deny',index:'threat'},
  {field:'cef_action',operator:'equals',value:'deny',index:'threat'},
 ];
 return p;
}
test('P0 mixed safely compiles explicitly declared JSON/KV/CEF/LEEF strict one-line families',()=>{
 const p=project();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const output=compilePair(p);
 assert.equal(output.manifest.engineVerified,false);
 assert.equal(output.manifest.targetImportVerified,false);
 assert.deepEqual(output.files.map(x=>x.name),['customized_mixed_demo.conf','customized_mixed_demo']);
 const recipe=recipeFromLegacyProject(p,'a'.repeat(64),4);
 assert.equal(recipe.sourceFormat,'mixed');
 assert.equal(recipe.bodyFormat,'mixed');
 assert.deepEqual(recipe.stages.slice(0,2),[
  {op:'split_event',boundary:'single-line'},
  {op:'dispatch_family',families:['json','kv','cef','leef'],mode:'strict_prefix'},
 ]);
 assert.equal(validateRecipePair({recipe,legacyProject:p}).ok,true);
 const converted=compileRecipePair({recipe,legacyProject:p});
 assert.deepEqual(converted.files,output.files);
 for(const file of converted.files)
  assert.equal(file.sha256,createHash('sha256').update(file.content).digest('hex'));
});
test('P0 mixed rejects silent auto fallback, unreviewed families and malformed allowlists',()=>{
 const p=project();
 const change:Array<(x:any)=>void>=[
  x=>{x.extraction.mixedFormats=['json'];},
  x=>{x.extraction.mixedFormats=['json','json'];},
  x=>{x.extraction.mixedFormats=['json','ruby'];},
  x=>{x.extraction.mixedFormats=['json','regex'];},
  x=>{x.extraction.mixedFormats=['kv','csv'];},
  x=>{x.extraction.mixedFormats=['json','syslog_rfc3164'];},
  x=>{x.extraction.mixedFormats=['json','kv','cef','leef','other'];},
  x=>{x.extraction.syslogBodyFormat='auto';},
  x=>{x.extraction.format='auto';},
 ];
 for(const mutate of change){
  const copy:any=structuredClone(p);mutate(copy);
  assert.equal(validateProject(copy).ok,false);
  assert.throws(()=>compilePair(copy),/Invalid parser project/);
 }
});
test('P0 mixed v0.2 routing is strict and refuses forged dispatch or any non-equivalent change',()=>{
 const p=project(),recipe=recipeFromLegacyProject(p,'a'.repeat(64),4);
 for(const mutate of [
  (x:any)=>{x.stages[1].families.reverse();},
  (x:any)=>{x.stages[1].mode='best_effort';},
  (x:any)=>{x.stages[1].families.push('ruby');},
  (x:any)=>{x.stages[1]={op:'parse_json'};},
  (x:any)=>{x.bodyFormat='json';},
  (x:any)=>{x.nativeVerified=true;},
  (x:any)=>{x.stages.unshift({op:'fallback_unparsed',mode:'ignore'});},
 ]){
  const modified:any=structuredClone(recipe);mutate(modified);
  const result=validateRecipePair({recipe:modified,legacyProject:p});
  assert.equal(result.ok,false,JSON.stringify(modified.stages[1]));
 }
});
