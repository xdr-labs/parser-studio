import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';

function project(){
 const p=sampleProject();
 p.projectId='draft-mixed_rfc5424_bodies';
 p.slug='mixed_rfc5424_bodies';
 p.receiver.port=6803;
 p.extraction={format:'mixed',
   mixedFormats:['json','kv','rfc5424_json','rfc5424_kv'] as any};
 p.normalization.topFields={
   src_ip:{normalized_name:'srcip',data_type:'ip'},
   action:{normalized_name:'action',data_type:'string'},
   'body.src_ip':{normalized_name:'wrapped_srcip',data_type:'ip'},
   'body.action':{normalized_name:'wrapped_action',data_type:'string'},
   syslog_timestamp:{normalized_name:'timestamp',data_type:'date',
      time_format:'iso8601',timezone:'UTC'},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[
  {field:'action',operator:'equals',value:'deny',index:'threat'},
  {field:'wrapped_action',operator:'equals',value:'deny',index:'threat'},
 ];
 return p;
}
test('explicit RFC5424 JSON/KV nested mixed stages compile to exact v0.1 paired SHA artifacts',()=>{
 const p=project();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const pair=compilePair(p);
 assert.ok(pair.manifest.warnings.some(text=>text.includes('RFC5424-wrapped JSON/KV')));
 assert.equal(pair.manifest.engineVerified,false);
 assert.equal(pair.manifest.targetImportVerified,false);
 assert.deepEqual(pair.files.map(x=>x.name),[
  'customized_mixed_rfc5424_bodies.conf','customized_mixed_rfc5424_bodies'
 ]);
 assert.ok(pair.files[0]!.content.includes('port 6803'));
 const recipe=recipeFromLegacyProject(p,'c'.repeat(64),4);
 assert.deepEqual(recipe.stages.slice(0,2),[
  {op:'split_event',boundary:'single-line'},
  {op:'dispatch_family',families:['json','kv','rfc5424_json','rfc5424_kv'],mode:'strict_prefix'},
 ]);
 assert.equal(validateRecipePair({recipe,legacyProject:p}).ok,true);
 const staged=compileRecipePair({recipe,legacyProject:p});
 assert.deepEqual(staged.files,pair.files);
 assert.equal(staged.recipeReceipt.nativeUserParserVerified,false);
 for(const f of staged.files)
  assert.equal(f.sha256,createHash('sha256').update(f.content).digest('hex'));
});
test('RFC5424 nested JSON/KV mixed port safety and unsupported families stay fail-closed',()=>{
 const p=project();
 const invalid:Array<(x:any)=>void>=[
  x=>{x.receiver.port=6799;},
  x=>{x.extraction.mixedFormats=['json','rfc5424_json','rfc5424_json'];},
  x=>{x.extraction.mixedFormats=['json','rfc5424_auto'];},
  x=>{x.extraction.mixedFormats=['json','rfc5424_csv'];},
  x=>{x.extraction.mixedFormats=['json','rfc5424_raw'];},
  x=>{x.extraction.mixedFormats=['json','kv','rfc5424_json','rfc5424_kv','cef'];},
  x=>{x.extraction.syslogBodyFormat='kv';},
 ];
 for(const fn of invalid){
  const copy:any=structuredClone(p);fn(copy);
  assert.equal(validateProject(copy).ok,false,JSON.stringify(copy));
  assert.throws(()=>compilePair(copy),/Invalid parser project/);
 }
});
test('strict RFC5424 JSON/KV mixed dispatch never accepts unreviewed code or forged family order',()=>{
 const p=project(),recipe=recipeFromLegacyProject(p,'d'.repeat(64),4);
 for(const fn of [
  (x:any)=>x.stages[1].families.reverse(),
  (x:any)=>x.stages[1].mode='best_effort',
  (x:any)=>x.stages[1].families.push('rfc5424_csv'),
  (x:any)=>x.stages[1].families.splice(1,1),
  (x:any)=>x.stages.splice(2,0,{op:'ruby_eval',code:'USER_INPUT'}),
 ]) {
  const untrusted:any=structuredClone(recipe);fn(untrusted);
  assert.equal(validateRecipePair({recipe:untrusted,legacyProject:p}).ok,false);
  assert.throws(()=>compileRecipePair({recipe:untrusted,legacyProject:p}),/Invalid ParserRecipe/);
 }
});
