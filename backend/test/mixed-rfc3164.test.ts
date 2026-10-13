import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';

function project(){
 const p=sampleProject();
 p.projectId='draft-mixed_rfc3164';
 p.slug='mixed_rfc3164';
 p.receiver.port=6802;
 p.extraction={format:'mixed',mixedFormats:['json','kv','rfc3164_kv'] as any};
 p.normalization.topFields={
  src_ip:{normalized_name:'srcip',data_type:'ip'},
  action:{normalized_name:'action',data_type:'string'},
  'body.src_ip':{normalized_name:'wrapped_srcip',data_type:'ip'},
  'body.action':{normalized_name:'wrapped_action',data_type:'string'},
  syslog_timestamp:{normalized_name:'yearless_header',data_type:'string'},
  syslog_time_policy:{normalized_name:'time_policy',data_type:'string'},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[
  {field:'action',operator:'equals',value:'deny',index:'threat'},
  {field:'wrapped_action',operator:'equals',value:'deny',index:'threat'},
 ];
 return p;
}
test('mixed RFC3164 KV compiles an explicitly reviewed versioned Ruby CONF pair',()=>{
 const p=project();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const output=compilePair(p);
 assert.equal(output.manifest.engineVerified,false);
 assert.equal(output.manifest.targetImportVerified,false);
 assert.deepEqual(output.files.map(x=>x.name),[
  'customized_mixed_rfc3164.conf','customized_mixed_rfc3164']);
 assert.ok(output.files[0]!.content.includes('port 6802'));
 const recipe=recipeFromLegacyProject(p,'c'.repeat(64),3);
 assert.deepEqual(recipe.stages.slice(0,2),[
  {op:'split_event',boundary:'single-line'},
  {op:'dispatch_family',families:['json','kv','rfc3164_kv'],mode:'strict_prefix'},
 ]);
 assert.equal(validateRecipePair({recipe,legacyProject:p}).ok,true);
 const pair=compileRecipePair({recipe,legacyProject:p});
 assert.deepEqual(pair.files,output.files);
 for(const file of pair.files)assert.equal(file.sha256,
  createHash('sha256').update(file.content).digest('hex'));
});
test('mixed RFC3164 never invents year or timezone and enforces same sensor CONF port >=6800',()=>{
 const p=project();
 const unsafe:Array<(p:any)=>void>=[
  x=>{x.receiver.port=6799;},
  x=>{x.normalization.topFields.syslog_timestamp={normalized_name:'timestamp',data_type:'date',time_format:'iso8601',timezone:'UTC'};},
  x=>{x.extraction.mixedFormats=['json','rfc3164_cef'];},
  x=>{x.extraction.mixedFormats=['json','rfc3164_json'];},
  x=>{x.extraction.mixedFormats=['json','rfc3164_kv','rfc3164_kv'];},
  x=>{x.extraction.mixedFormats=['json','rfc3164_kv','rfc5424_kv'];},
  x=>{x.extraction.mixedFormats=['json','rfc3164_kv','csv'];},
 ];
 for(const change of unsafe){
  const copy:any=structuredClone(p);change(copy);
  assert.equal(validateProject(copy).ok,false,JSON.stringify(copy));
  assert.throws(()=>compilePair(copy),/Invalid parser project/);
 }
});
test('mixed RFC3164 recipe never silently accepts reordering or an unreviewed operator',()=>{
 const p=project(),recipe=recipeFromLegacyProject(p,'d'.repeat(64),3);
 for(const change of [
  (r:any)=>r.stages[1].families.reverse(),
  (r:any)=>r.stages[1].families.push('rfc3164_cef'),
  (r:any)=>r.stages[1].mode='best_effort',
  (r:any)=>r.stages.splice(2,0,{op:'eval_ruby',source:'NOT_ALLOWED'}),
  (r:any)=>r.nativeVerified=true,
 ]){
  const other:any=structuredClone(recipe);change(other);
  assert.equal(validateRecipePair({recipe:other,legacyProject:p}).ok,false);
  assert.throws(()=>compileRecipePair({recipe:other,legacyProject:p}),/Invalid ParserRecipe/);
 }
});
