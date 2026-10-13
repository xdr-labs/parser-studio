import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';

function project(){
 const p=sampleProject();
 p.projectId='draft-mixed_rfc3164_cefleef';p.slug='mixed_rfc3164_cefleef';
 p.receiver.port=6804;
 p.extraction={format:'mixed',mixedFormats:[
  'json','kv','rfc3164_cef','rfc3164_leef'] as any};
 p.normalization.topFields={
  src_ip:{normalized_name:'srcip',data_type:'ip'},
  action:{normalized_name:'action',data_type:'string'},
  'body.src':{normalized_name:'wrapped_srcip',data_type:'ip'},
  'body.act':{normalized_name:'wrapped_action',data_type:'string'},
  'body.dpt':{normalized_name:'cef_port',data_type:'port'},
  'body.dstPort':{normalized_name:'leef_port',data_type:'port'},
  syslog_timestamp:{normalized_name:'yearless_time',data_type:'string'},
  syslog_time_policy:{normalized_name:'time_policy',data_type:'string'},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[
  {field:'action',operator:'equals',value:'deny',index:'threat'},
  {field:'wrapped_action',operator:'equals',value:'deny',index:'threat'},
 ];
 return p;
}
test('strict RFC3164 CEF/LEEF mixed parser builds identical v0.1 and v0.2 DRAFT artifact hashes',()=>{
 const p=project();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const pair=compilePair(p);
 assert.equal(pair.manifest.targetImportVerified,false);
 assert.equal(pair.manifest.engineVerified,false);
 assert.ok(pair.manifest.warnings.some(w=>w.includes('RFC3164 CEF/LEEF')));
 const recipe=recipeFromLegacyProject(p,'e'.repeat(64),4);
 assert.deepEqual(recipe.stages.slice(0,2),[
  {op:'split_event',boundary:'single-line'},
  {op:'dispatch_family',families:['json','kv','rfc3164_cef','rfc3164_leef'],mode:'strict_prefix'},
 ]);
 assert.equal(validateRecipePair({recipe,legacyProject:p}).ok,true);
 const staged=compileRecipePair({recipe,legacyProject:p});
 assert.deepEqual(staged.files,pair.files);
 assert.ok(pair.files[0]!.content.includes('port 6804'));
 for(const f of pair.files)assert.equal(f.sha256,
  createHash('sha256').update(f.content).digest('hex'));
});
test('yearless RFC3164 CEF/LEEF allowlist forbids timestamp inference, unsafe ports and unknown branches',()=>{
 const p=project();
 const changes:Array<(p:any)=>void>=[
  x=>{x.receiver.port=6799;},
  x=>{x.normalization.topFields.syslog_timestamp={
   normalized_name:'event_time',data_type:'date',time_format:'iso8601',timezone:'UTC'};},
  x=>{x.extraction.mixedFormats=['json','rfc3164_cef','rfc3164_cef'];},
  x=>{x.extraction.mixedFormats=['json','rfc3164_leef','rfc3164_json'];},
  x=>{x.extraction.mixedFormats=['json','rfc3164_raw'];},
  x=>{x.extraction.mixedFormats=['json','rfc3164_csv'];},
  x=>{x.extraction.mixedFormats=['json','kv','rfc3164_cef','rfc3164_leef','cef'];},
 ];
 for(const change of changes){
  const candidate:any=structuredClone(p);change(candidate);
  assert.equal(validateProject(candidate).ok,false,JSON.stringify(candidate));
  assert.throws(()=>compilePair(candidate),/Invalid parser project/);
 }
});
test('strict RFC3164 CEF/LEEF staged compiler rejects unexpected operators or forged family order',()=>{
 const p=project(),recipe=recipeFromLegacyProject(p,'f'.repeat(64),4);
 for(const change of [
  (x:any)=>x.stages[1].families.reverse(),
  (x:any)=>x.stages[1].mode='guess_body',
  (x:any)=>x.stages[1].families.push('rfc3164_raw'),
  (x:any)=>x.stages[1].families.pop(),
  (x:any)=>x.stages.splice(2,0,{op:'eval',code:'unsafe'}),
 ]){
  const candidate:any=structuredClone(recipe);change(candidate);
  assert.equal(validateRecipePair({recipe:candidate,legacyProject:p}).ok,false);
  assert.throws(()=>compileRecipePair({recipe:candidate,legacyProject:p}),
   /Invalid ParserRecipe/);
 }
});
