import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import type {ParserProject} from '../src/types.js';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import {validateRecipePair,compileRecipePair,recipeFromLegacyProject} from '../src/parser-recipe-v02.js';

function candidate(format:ParserProject['extraction']['format']='json'){
 const project=sampleProject();
 project.projectId='draft-synthetic_recipe';
 project.extraction={format,
  ...(format==='csv'?{csvColumns:['source','destination','action'],csvDelimiter:',' as const}:{}),
  ...(format==='syslog_rfc5424'?{syslogBodyFormat:'cef' as const}:{})};
 // Only equals predicates are represented in the current reviewed UI stage.
 project.classification.rules=project.classification.rules.filter(r=>r.operator==='equals');
 if(format==='csv'){
  project.normalization.topFields={
   action:{normalized_name:'action',data_type:'string'},
   source:{normalized_name:'srcip',data_type:'ip'}};
  project.normalization.nsFields={
   destination:{normalized_name:'dstport',data_type:'port'}};
 }
 if(format==='syslog_rfc5424'){
  project.normalization.topFields={
   'body.act':{normalized_name:'action',data_type:'string'},
   'body.src':{normalized_name:'srcip',data_type:'ip'}};
  project.normalization.nsFields={
   'body.dpt':{normalized_name:'dstport',data_type:'port'},
   syslog_timestamp:{normalized_name:'event_time',data_type:'date',
    time_format:'iso8601',timezone:'UTC'}};
  project.classification.rules=[
   {field:'action',operator:'equals',value:'deny',index:'threat'}];
 }
 const recipe=recipeFromLegacyProject(project,'a'.repeat(64),2);
 return {recipe,legacyProject:project};
}


test('P0-AP3 bounded mapping budget keeps sixty source fields but rejects sixty-one',()=>{
 const project=candidate('generic_structural').legacyProject;
 project.normalization.topFields={};project.normalization.nsFields={};project.normalization.vendorFields={};
 for(let i=0;i<60;i++)project.normalization.vendorFields['field_'+i]={
  normalized_name:'field_'+i,data_type:'string',
 };
 project.classification.rules=[];
 const recipe=recipeFromLegacyProject(project,'c'.repeat(64),1);
 assert.equal(recipe.stages.filter(stage=>stage.op==='map_field').length,60);
 assert.equal(validateRecipePair({recipe,legacyProject:project}).ok,true);
 project.normalization.vendorFields.field_60={normalized_name:'field_60',data_type:'string'};
 assert.throws(()=>recipeFromLegacyProject(project,'c'.repeat(64),1),/UNSUPPORTED_MAPPING_COUNT/);
});

test('P0-AP3 v0.2 compiles same native-qualified Ruby + CONF bytes for allowed families',()=>{
 for(const format of ['json','kv','csv','cef','leef','syslog_rfc5424','generic_structural'] as const){
  const input=candidate(format);
  assert.equal(validateRecipePair(input).ok,true,format);
  const compiled=compileRecipePair(input);
  const legacy=compilePair(input.legacyProject);
  assert.deepEqual(compiled.files,legacy.files,format);
  assert.deepEqual(compiled.manifest,legacy.manifest,format);
  assert.equal(compiled.recipeReceipt.compilerMode,'V01_EQUIVALENT_SUBSET');
  assert.equal(compiled.recipeReceipt.nativeUserParserVerified,false);
  assert.equal(compiled.recipeReceipt.targetImportVerified,false);
  assert.equal(compiled.recipeReceipt.sourceHashVerifiedAgainstEvents,false);
  assert.equal(compiled.recipeReceipt.sampleEventCount,2);
  assert.match(compiled.recipeReceipt.recipeSha256,/^[0-9a-f]{64}$/);
  for(const f of compiled.files)
   assert.equal(createHash('sha256').update(f.content).digest('hex'),f.sha256);
  assert.deepEqual(compileRecipePair(input),compiled);
 }
});

test('P0-AI2 split and merge stages preserve exact v0.1 Ruby + CONF bytes',()=>{
 const input=candidate();
 input.legacyProject.normalization.topFields.endpoint={normalized_name:'endpoint',data_type:'string'};
 input.legacyProject.enrichment=[
  {operator:'split_field',source:'endpoint',delimiter:':',targets:['log.endpoint_host','log.endpoint_port']},
  {operator:'merge_fields',sources:['log.endpoint_host','log.endpoint_port'],delimiter:':',target:'log.endpoint_joined'},
 ];
 input.recipe=recipeFromLegacyProject(input.legacyProject,'a'.repeat(64),2);
 assert.deepEqual(input.recipe.stages.filter(x=>x.op==='split_field'||x.op==='merge_fields'),[
  {op:'split_field',source:'endpoint',delimiter:':',targets:['log.endpoint_host','log.endpoint_port']},
  {op:'merge_fields',sources:['log.endpoint_host','log.endpoint_port'],delimiter:':',target:'log.endpoint_joined'},
 ]);
 assert.equal(validateRecipePair(input).ok,true);
 assert.deepEqual(compileRecipePair(input).files,compilePair(input.legacyProject).files);
 const changed:any=structuredClone(input);
 changed.recipe.stages.find((x:any)=>x.op==='split_field').delimiter='|';
 assert.equal(validateRecipePair(changed).ok,false);
 assert.throws(()=>compileRecipePair(changed),/Invalid ParserRecipe/);
});

test('P0-AP3 reject forged native, unknown operators, stale/project mismatch and unsafe mapping',()=>{
 const base=candidate();
 const mutate:Array<(value:any)=>void>=[
  x=>{x.recipe.nativeVerified=true;},
  x=>{x.recipe.targetVerified=true;},
  x=>{x.recipe.compilerMode='EXECUTE_RUBY';},
  x=>{x.recipe.stages.splice(1,0,{op:'exec_ruby',value:'puts 1'});},
  x=>{x.recipe.stages.unshift({op:'split_event',boundary:'single-line'});},
  x=>{x.recipe.stages[1]={op:'parse_leef'};},
  x=>{x.recipe.stages.splice(-1,1);},
  x=>{x.recipe.stages[0].boundary='blank-line';},
  x=>{x.recipe.stages.find((s:any)=>s.op==='map_field').source='__proto__.secret';},
  x=>{x.recipe.stages.find((s:any)=>s.op==='map_field').target='system.secret';},
  x=>{x.recipe.stages.find((s:any)=>s.op==='cast_type').data_type='boolean';},
  x=>{x.recipe.sample.sha256='a'.repeat(63)+'G';},
  x=>{x.recipe.sample.events=501;},
  x=>{x.recipe.sourceFormat='rfc3164';},
  x=>{x.recipe.stages.push({op:'eval_jsonata',expression:'$eval()'});},
  x=>{x.recipe.secret='CUSTOMER_PRIVATE_DATA';},
  x=>{x.extra='CUSTOMER_PRIVATE_DATA';},
  x=>{x.legacyProject.projectId='different';},
  x=>{x.legacyProject.normalization.topFields.action.normalized_name='unexpected';},
  x=>{x.legacyProject.receiver.port=0;},
  x=>{x.legacyProject.unsupportedOpaqueBlocks=[{source:'opaque'}];},
  x=>{x.legacyProject.enrichment=[
   {operator:'set_const',target:'custom.secret',value:'value'}];},
  x=>{x.legacyProject.classification.rules.push(
   {field:'srcip',operator:'exists',index:'session'});},
 ];
 for(const fn of mutate){
  const input:any=structuredClone(base);
  fn(input);
  const result=validateRecipePair(input);
  assert.equal(result.ok,false,'expected explicit reject for '+JSON.stringify(input.recipe?.sourceFormat));
  assert.throws(()=>compileRecipePair(input),/Invalid ParserRecipe/);
  assert.equal(JSON.stringify(result).includes('CUSTOMER_PRIVATE_DATA'),false);
 }
});

test('P0-AP3 reject changed RFC5424 stage order, classification semantics and cast policy',()=>{
 const base=candidate('syslog_rfc5424');
 const mutate:Array<(input:any)=>void>=[
  x=>{x.recipe.stages[1].mode='relaxed';},
  x=>{x.recipe.stages[2].op='parse_kv';},
  x=>{x.recipe.bodyFormat='leef';},
  x=>{x.recipe.stages.find((s:any)=>s.op==='classify').rules[0].value='allow';},
  x=>{x.recipe.stages.find((s:any)=>s.op==='map_field').group='ns_fields';},
  x=>{x.recipe.stages.find((s:any)=>s.op==='map_field').data_type='integer';},
  x=>{x.recipe.stages.find((s:any)=>s.op==='cast_type'&&s.target==='event_time').timezone='PST';},
 ];
 for(const fn of mutate){const input:any=structuredClone(base);fn(input);
  assert.equal(validateRecipePair(input).ok,false);
 }
});

test('P0-AP3 rejects all lossy v0.1 projections before generating a reviewed v0.2 recipe',()=>{
 const checks:Array<(p:ParserProject)=>void>=[
  p=>{p.enrichment=[{operator:'set_const',target:'log.label',value:'x'}];},
  p=>{p.extraction={format:'syslog_rfc5424',syslogBodyFormat:'raw'};},
  p=>{p.extraction.maxDepth=3;},
  p=>{p.receiver.tcpFraming='delimiter';p.receiver.delimiter='|';},
  p=>{p.classification.rules=[{field:'srcip',operator:'exists',index:'session'}];},
  p=>{p.unsupportedOpaqueBlocks=[{source:'opaque'}];},
 ];
 for(const fn of checks){const project=candidate().legacyProject;fn(project);
  assert.throws(()=>recipeFromLegacyProject(project,'a'.repeat(64),2),/UNSUPPORTED_RECIPE_PROJECTION/);
 }
});


test("reviewed RFC3164 + bounded Regex body projects to exact v0.2 stages and v0.1 artifacts",()=>{
 const project=sampleProject();
 project.projectId="draft-syslog_regex";
 project.receiver.port=7123;
 project.extraction={format:"syslog_rfc3164",syslogBodyFormat:"regex",
  pattern:"^%FTD-\\d-\\d+: Built \\w+ \\w+ connection (?<connection_id>\\d+) for [^:]+:(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<src_port>\\d+) to [^:]+:(?<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<dst_port>\\d+)$"};
 project.normalization.topFields={
  "body.src_ip":{normalized_name:"srcip",data_type:"ip"},
  "body.dst_port":{normalized_name:"dstport",data_type:"port"},
 };
 project.normalization.nsFields={};project.normalization.vendorFields={};
 project.classification.rules=[];
 const recipe=recipeFromLegacyProject(project,"b".repeat(64),2);
 assert.equal(recipe.sourceFormat,"syslog_rfc3164");
 assert.equal(recipe.bodyFormat,"regex");
 assert.deepEqual(recipe.stages.slice(0,3),[
  {op:"split_event",boundary:"single-line"},
  {op:"unwrap_syslog",version:3164,mode:"strict_header"},
  {op:"parse_regex",pattern:project.extraction.pattern},
 ]);
 const input={recipe,legacyProject:project};
 assert.equal(validateRecipePair(input).ok,true,JSON.stringify(validateRecipePair(input)));
 assert.deepEqual(compileRecipePair(input).files,compilePair(project).files);
 const forged:any=structuredClone(input);
 forged.recipe.stages[2].pattern="(?<x>.*)+";
 assert.equal(validateRecipePair(forged).ok,false);
});
