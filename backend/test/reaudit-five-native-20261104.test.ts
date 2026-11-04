import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {validateBoundedRegexPattern,validateProject} from '../src/validate.js';
import {recipeFromLegacyProject,validateRecipePair} from '../src/parser-recipe-v02.js';
import {sampleProject} from './fixture.js';
import type {FieldRule,ParserProject} from '../src/types.js';

const rubyInstalled=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function project(maps:Record<string,FieldRule>,family:boolean):ParserProject{
 const p=sampleProject();
 p.normalization.topFields=maps;
 p.normalization.vendorFields={};
 p.normalization.nsFields={};
 p.classification.rules=[];
 if(family){
  p.normalization.topFields={event_type:{normalized_name:'event_type',data_type:'string'}};
  p.normalization.eventProfiles={
   discriminator:'event_type',unknown:'reject',variants:[
    {name:'security',equals:'security',topFields:maps,nsFields:{},vendorFields:{}},
    {name:'other',equals:'other',topFields:{username:{normalized_name:'username',data_type:'string'}},nsFields:{},vendorFields:{}},
   ],
  };
 }
 const verdict=validateProject(p);
 assert.equal(verdict.ok,true,JSON.stringify(verdict.issues));
 return p;
}

function native(p:ParserProject,input:Record<string,unknown>){
 const compiled=compilePair(p);
 const ruby=compiled.files.find(f=>!f.name.endsWith('.conf'))!.content;
 const code=[
  "require 'json'","require 'base64'","require 'time'","require 'ipaddr'","require 'csv'",
  'parser_class=Class.new',
  "parser_class.class_eval(Base64.strict_decode64('"+Buffer.from(ruby).toString('base64')+"'))",
  'parser=parser_class.new',
  'parser.parse(STDIN.read){|_time,record| puts JSON.generate(record)}',
 ].join('\n');
 const inputText=JSON.stringify({
  ...input,...(p.normalization.eventProfiles?{event_type:'security'}:{}),
 });
 const response=spawnSync('ruby',['-e',code],{
  encoding:'utf8',input:inputText,timeout:9000,maxBuffer:1024*1024,
 });
 assert.equal(response.status,0,response.stderr||String(response.error));
 assert.ok(response.stdout.length>0,'Ruby emitted no record');
 return JSON.parse(response.stdout) as Record<string,unknown>;
}

test('nested alternation, including bounded repetitions, is rejected by both compiler validators',()=>{
 for(const p of ['^(?<field>((a|aa))+)$','^(?<field>((a|aa)){2,40})$','^(?<field>(?:a|aa)+)$']){
  assert.equal(validateBoundedRegexPattern(p),'regex_unsafe_construct',p);
 }
 assert.equal(validateBoundedRegexPattern('^(?<field>tcp|udp)$'),null);
});

for(const family of [false,true]){
 const label=family?'conditional family':'single event';
 test('generated Ruby '+label+' rejects impossible calendar dates and preserves valid leap day',
  {skip:!rubyInstalled},()=>{
   const p=project({time:{normalized_name:'timestamp',data_type:'date',
     time_format:'iso8601',timezone:'UTC'}},family);
   const invalid=native(p,{time:'2026-02-30T12:00:00Z'});
   assert.equal(invalid.parser_err_stage,'normalization');
   assert.ok(!('timestamp' in invalid));
   const valid=native(p,{time:'2024-02-29T12:00:00Z'});
   assert.equal(valid.timestamp,Date.parse('2024-02-29T12:00:00Z'));
 });
 test('generated Ruby '+label+' honors exact JSONata literal-root and nested source selectors',
  {skip:!rubyInstalled},()=>{
   for(const kind of ['literal_root','nested'] as const){
    const p=project({'source.ip':{normalized_name:'srcip',data_type:'ip',source_path_kind:kind}},family);
    const flat=native(p,{'source.ip':'203.0.113.47'});
    const nested=native(p,{source:{ip:'192.0.2.19'}});
    const both=native(p,{'source.ip':'203.0.113.47',source:{ip:'192.0.2.19'}});
    if(kind==='literal_root'){
     assert.equal(flat.srcip,'203.0.113.47');
     assert.ok(!('srcip' in nested));
    }else{
     assert.equal(nested.srcip,'192.0.2.19');
     assert.ok(!('srcip' in flat));
    }
    assert.equal(both.parser_err_stage,'normalization');
   }
 });
 test('generated Ruby '+label+' rejects contradicting IP protocol and L4 name',
  {skip:!rubyInstalled},()=>{
   const p=project({
    p:{normalized_name:'proto',data_type:'integer'},
    p_name:{normalized_name:'proto_name',data_type:'string'},
   },family);
   const invalid=native(p,{p:6,p_name:'UDP'});
   assert.equal(invalid.parser_err_stage,'normalization');
   const tcp=native(p,{p:6,p_name:'TCP'});
   assert.equal(tcp.proto,6);
   assert.equal(tcp.proto_name,'TCP');
   const icmp=native(p,{p:58,p_name:'ICMP'});
   assert.equal(icmp.proto,58);
 });
 test('generated Ruby '+label+' serializes structured objects as the browser does',
  {skip:!rubyInstalled},()=>{
   const p=project({details:{normalized_name:'custom.payload',data_type:'string'}},family);
   const output=native(p,{details:{a:'b',n:1}});
   assert.equal((output.custom as {payload?:unknown}).payload,'{"a":"b","n":1}');
 });
}

test('ParserRecipe v0.2 cannot silently reinterpret an approved JSONata literal-root selector',()=>{
 const projectIR=project({'source.ip':{
  normalized_name:'srcip',data_type:'ip',source_path_kind:'literal_root',
 }},false);
 projectIR.projectId='draft-synthetic_recipe';
 const recipe=recipeFromLegacyProject(projectIR,'a'.repeat(64),1);
 const stage=recipe.stages.find(s=>s.op==='map_field');
 assert.ok(stage&&stage.op==='map_field');
 assert.equal(stage.source_path_kind,'literal_root');
 assert.equal(validateRecipePair({recipe,legacyProject:projectIR}).ok,true);
 const forged=structuredClone(recipe);
 const replaced=forged.stages.find(s=>s.op==='map_field');
 assert.ok(replaced&&replaced.op==='map_field');
 replaced.source_path_kind='nested';
 assert.equal(validateRecipePair({recipe:forged,legacyProject:projectIR}).ok,false);
});
