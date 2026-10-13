import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';

function mixedSyslogProject(){
 const p=sampleProject();
 p.projectId='draft-mixed_syslog';
 p.slug='mixed_syslog';
 p.receiver.port=6801;
 p.extraction={format:'mixed',
  mixedFormats:['json','kv','rfc5424_cef','rfc5424_leef'] as any};
 p.normalization.topFields={
  src_ip:{normalized_name:'srcip',data_type:'ip'},
  dst_port:{normalized_name:'dstport',data_type:'port'},
  action:{normalized_name:'action',data_type:'string'},
  'body.src':{normalized_name:'syslog_srcip',data_type:'ip'},
  'body.dpt':{normalized_name:'syslog_cef_port',data_type:'port'},
  'body.dstPort':{normalized_name:'syslog_leef_port',data_type:'port'},
  'body.act':{normalized_name:'syslog_action',data_type:'string'},
  syslog_timestamp:{normalized_name:'event_time',data_type:'date',
   time_format:'iso8601',timezone:'UTC'},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[
  {field:'action',operator:'equals',value:'deny',index:'threat'},
  {field:'syslog_action',operator:'equals',value:'deny',index:'threat'},
 ];
 return p;
}
test('P0 mixed RFC5424 wrapped CEF/LEEF supports exact stage+native-qualified output',()=>{
 const p=mixedSyslogProject();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const result=compilePair(p);
 assert.equal(result.manifest.engineVerified,false);
 assert.equal(result.manifest.targetImportVerified,false);
 assert.ok(result.manifest.warnings.some(w=>
  w.includes("Only explicitly allowlisted RFC5424-wrapped CEF/LEEF")));
 assert.deepEqual(result.files.map(f=>f.name),
  ['customized_mixed_syslog.conf','customized_mixed_syslog']);
 const recipe=recipeFromLegacyProject(p,'a'.repeat(64),4);
 assert.equal(recipe.sourceFormat,'mixed');
 assert.equal(recipe.bodyFormat,'mixed');
 assert.deepEqual(recipe.stages.slice(0,2),[
  {op:'split_event',boundary:'single-line'},
  {op:'dispatch_family',
   families:['json','kv','rfc5424_cef','rfc5424_leef'],mode:'strict_prefix'},
 ]);
 assert.equal(validateRecipePair({recipe,legacyProject:p}).ok,true);
 assert.deepEqual(compileRecipePair({recipe,legacyProject:p}).files,result.files);
 for(const file of result.files)assert.equal(file.sha256,
  createHash('sha256').update(file.content).digest('hex'));
});
test('P0 mixed RFC5424 needs Syslog port >=6800 and rejects unsupported envelopes and ambiguous family rules',()=>{
 const p=mixedSyslogProject();
 const mutations:Array<(p:any)=>void>=[
  x=>{x.receiver.port=6799;},
  x=>{x.extraction.mixedFormats=['json','kv','rfc3164_cef'];},
  x=>{x.extraction.mixedFormats=['json','kv','rfc5424'];},
  x=>{x.extraction.mixedFormats=['json','kv','rfc5424_csv'];},
  x=>{x.extraction.mixedFormats=['json','kv','rfc5424_cef','rfc5424_cef'];},
  x=>{x.extraction.mixedFormats=['json','kv','rfc5424_cef','rfc5424_leef','cef','leef','raw'];},
  x=>{x.extraction.mixedFormats=['json','kv','rfc5424_cef','rfc5424_leef','cef','leef','rfc3164_kv'];},
  x=>{x.extraction.syslogBodyFormat='auto';},
 ];
 for(const change of mutations){
  const copy:any=structuredClone(p);change(copy);
  assert.equal(validateProject(copy).ok,false,
   JSON.stringify(copy.extraction)+':'+copy.receiver.port);
  assert.throws(()=>compilePair(copy),/Invalid parser project/);
 }
});
test('P0 staged mixed RFC5424 selection fails closed on forged order or unapproved routing',()=>{
 const p=mixedSyslogProject(),recipe=recipeFromLegacyProject(p,'b'.repeat(64),4);
 for(const change of [
  (r:any)=>r.stages[1].families.reverse(),
  (r:any)=>r.stages[1].mode='best_effort',
  (r:any)=>r.stages[1].families.push('rfc3164_cef'),
  (r:any)=>r.stages[1].families[2]='rfc5424_kv',
  (r:any)=>r.stages.push({op:'execute_ruby',source:'SECRET'}),
 ]){
  const candidate:any=structuredClone(recipe);change(candidate);
  assert.equal(validateRecipePair({recipe:candidate,legacyProject:p}).ok,false);
  assert.throws(()=>compileRecipePair({recipe:candidate,legacyProject:p}),
   /Invalid ParserRecipe/);
 }
});
