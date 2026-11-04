import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {validateBoundedRegexPattern,validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
function project(source:string,target:string,type:'ip'|'integer'|'string',family:boolean){
 const p=sampleProject();
 p.normalization.topFields={[source]:{normalized_name:target,data_type:type}};
 p.normalization.nsFields={};
 p.normalization.vendorFields={};
 p.classification.rules=[];
 if(family){
  p.normalization.topFields={event_type:{normalized_name:'event_type',data_type:'string'}};
  p.normalization.eventProfiles={discriminator:'event_type',unknown:'reject',variants:[
   {name:'security',equals:'security',topFields:{[source]:{normalized_name:target,data_type:type}},nsFields:{},vendorFields:{}},
   {name:'other',equals:'other',topFields:{username:{normalized_name:'username',data_type:'string'}},nsFields:{},vendorFields:{}},
  ]};
 }
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p).issues));
 return p;
}
function native(source:string,target:string,type:'ip'|'integer'|'string',value:unknown,family=false){
 const p=project(source,target,type,family);
 const code=compilePair(p).files.find(f=>!f.name.endsWith('.conf'))!.content;
 const program=[
  "require 'json'","require 'base64'","require 'csv'","require 'time'","require 'ipaddr'",
  'klass = Class.new',
  "klass.class_eval(Base64.strict_decode64('"+Buffer.from(code).toString('base64')+"'))",
  'parser = klass.new',
  'parser.parse(STDIN.read){|_time,record| puts JSON.generate(record)}',
 ].join('\n');
 const input={...(value as Record<string,unknown>),...(family?{event_type:'security'}:{})};
 const result=spawnSync('ruby',['-e',program],{encoding:'utf8',input:JSON.stringify(input),timeout:15000,maxBuffer:1024*1024});
 assert.equal(result.status,0,result.stderr||String(result.error));
 return JSON.parse(result.stdout) as Record<string,unknown>;
}
test('bounded project rejects nested counted repetition that formerly froze the browser preview',()=>{
 for(const expression of ['^(?<field>(a{1,3})+)$','^(?<field>(?:a{1,3}){2,10})$'])
  assert.equal(validateBoundedRegexPattern(expression),'regex_unsafe_construct');
 assert.equal(validateBoundedRegexPattern('^(?<field>a{1,3})$'),null);
});
for(const family of [false,true]){
 test('native '+(family?'conditional family':'single')+' rejects conflicting dotted and nested JSON sources',
   {skip:!rubyAvailable},()=>{
   const ambiguous=native('source.ip','srcip','ip',{'source.ip':'203.0.113.47',source:{ip:'192.0.2.19'}},family);
   assert.equal(ambiguous.parser_err_stage,'normalization');
   assert.ok(!('srcip' in ambiguous));
   assert.ok(!JSON.stringify(ambiguous).includes('203.0.113.47'));
   const flat=native('source.ip','srcip','ip',{'source.ip':'203.0.113.47'},family);
   assert.equal(flat.srcip,'203.0.113.47');
   const nested=native('source.ip','srcip','ip',{source:{ip:'192.0.2.19'}},family);
   assert.equal(nested.srcip,'192.0.2.19');
 });
 test('native '+(family?'conditional family':'single')+' enforces official IP protocol semantics',
   {skip:!rubyAvailable},()=>{
   const invalidNumber=native('protocol-id','proto','integer',{'protocol-id':999},family);
   assert.equal(invalidNumber.parser_err_stage,'normalization');
   assert.ok(!('proto' in invalidNumber));
   const validNumber=native('protocol-id','proto','integer',{'protocol-id':6},family);
   assert.equal(validNumber.proto,6);
   const invalidName=native('protocol','proto_name','string',{protocol:'HTTPS'},family);
   assert.equal(invalidName.parser_err_stage,'normalization');
   assert.ok(!('proto_name' in invalidName));
   const validName=native('protocol','proto_name','string',{protocol:'TCP'},family);
   assert.equal(validName.proto_name,'TCP');
 });
}
