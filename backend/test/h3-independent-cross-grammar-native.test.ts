/**
 * H3 source-grammar golden truth is manually authored, not inferred from
 * parser/browser output. All fixtures are fixed synthetic security telemetry.
 * The full raw input never appears in a persisted CI evidence artifact.
 */
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import type {ParserProject} from '../src/types.js';

type Format='json'|'kv'|'csv'|'cef'|'leef'|'syslog_rfc5424'|'syslog_rfc3164'|'regex';
type Golden={
  format:Format;
  good:string;
  bad:string;
  srcField:string;
  actionField:string;
  expectedIp:string;
  expectedAction:'deny'|'allow';
};
const CORPUS:Golden[]=[
 {format:'json',good:'{"srcip":"192.0.2.10","action":"deny","note":"한글"}',
  bad:'{"srcip":"not-an-ip","action":"deny","note":"한글"}',
  srcField:'srcip',actionField:'action',expectedIp:'192.0.2.10',expectedAction:'deny'},
 {format:'kv',good:'srcip=192.0.2.11 action=allow note=한글',
  bad:'srcip=not-an-ip action=allow note=한글',
  srcField:'srcip',actionField:'action',expectedIp:'192.0.2.11',expectedAction:'allow'},
 {format:'csv',good:'192.0.2.12,deny,한글',
  bad:'not-an-ip,deny,한글',
  srcField:'srcip',actionField:'action',expectedIp:'192.0.2.12',expectedAction:'deny'},
 {format:'cef',good:'CEF:0|Acme|Edge|1.0|100|Threat|7|src=192.0.2.13 act=allow cs1Label=한글',
  bad:'CEF:0|Acme|Edge|1.0|100|Threat|7|src=not-an-ip act=allow cs1Label=한글',
  srcField:'src',actionField:'act',expectedIp:'192.0.2.13',expectedAction:'allow'},
 {format:'leef',good:'LEEF:2.0|Acme|Edge|1.0|100|^|src=192.0.2.14^action=deny^note=한글',
  bad:'LEEF:2.0|Acme|Edge|1.0|100|^|src=not-an-ip^action=deny^note=한글',
  srcField:'src',actionField:'action',expectedIp:'192.0.2.14',expectedAction:'deny'},
 {format:'syslog_rfc5424',
  good:'<134>1 2026-11-07T12:00:00Z edge01 app - ID - srcip=192.0.2.15 action=allow note=한글',
  bad:'<134>1 2026-11-07T12:00:00Z edge01 app - ID - srcip=not-an-ip action=allow note=한글',
  srcField:'body.srcip',actionField:'body.action',expectedIp:'192.0.2.15',expectedAction:'allow'},
 {format:'syslog_rfc3164',
  good:'<134>Nov  7 12:00:00 edge01 app: srcip=192.0.2.16 action=deny note=한글',
  bad:'<134>Nov  7 12:00:00 edge01 app: srcip=not-an-ip action=deny note=한글',
  srcField:'body.srcip',actionField:'body.action',expectedIp:'192.0.2.16',expectedAction:'deny'},
 {format:'regex',good:'src=192.0.2.17 action=allow',
  bad:'src=999.999.999.999 action=allow',
  srcField:'srcip',actionField:'action',expectedIp:'192.0.2.17',expectedAction:'allow'},
];

function project(item:Golden,family=false):ParserProject{
 const p=sampleProject();
 p.projectId='h3-golden-'+item.format;
 p.slug='h3_'+item.format;
 p.product='H3 security synthetic '+item.format;
 p.normalization.topFields={
   [item.srcField]:{normalized_name:'srcip',data_type:'ip'},
   [item.actionField]:{normalized_name:'action',data_type:'string'},
 };
 p.normalization.nsFields={};
 p.normalization.vendorFields={};
 p.classification={defaultIndex:'syslog',rules:[
   {field:'action',operator:'equals',value:'deny',index:'threat'},
 ]};
 if(item.format==='csv')p.extraction={format:'csv',csvColumns:['srcip','action','note'],csvDelimiter:','};
 else if(item.format==='syslog_rfc5424'||item.format==='syslog_rfc3164')
   p.extraction={format:item.format,syslogBodyFormat:'kv'};
 else if(item.format==='regex')p.extraction={format:'regex',
   pattern:String.raw`^src=(?<srcip>[\d.]+) action=(?<action>deny|allow)$`};
 else p.extraction={format:item.format};
 if(family)p.normalization.eventProfiles={
  discriminator:item.actionField,unknown:'reject',variants:[
   {name:'allow',equals:'allow',topFields:{},nsFields:{},vendorFields:{}},
   {name:'deny',equals:'deny',topFields:{},nsFields:{},vendorFields:{}},
  ],
 };
 return p;
}
const available=spawnSync('ruby',['-v'],{encoding:'utf8',timeout:3000}).status===0;
const required=process.env.PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED==='1';
const sha=(raw:string)=>createHash('sha256').update(raw,'utf8').digest('hex');

function native(p:ParserProject,raw:string[]):Array<Record<string,unknown>>{
 const pair=compilePair(p);
 assert.equal(pair.manifest.status,'DRAFT');
 assert.equal(pair.manifest.targetImportVerified,false);
 const code=pair.files.find(x=>!x.name.endsWith('.conf'))?.content;
 assert.ok(code);
 const harness=[
   "require 'json'","require 'base64'","require 'date'","require 'time'",
   "require 'csv'","require 'ipaddr'",
   "klass=Class.new",
   "klass.class_eval(Base64.strict_decode64(STDIN.gets.strip),'h3-native',1)",
   "parser=klass.new",
   "rows=[]",
   "JSON.parse(STDIN.read).each{|line| parser.parse(line){|_time,record|rows << record}}",
   "STDOUT.write(JSON.generate(rows))",
 ].join('\n');
 const result=spawnSync('ruby',['-e',harness],{
   encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
   input:Buffer.from(code,'utf8').toString('base64')+'\n'+JSON.stringify(raw),
 });
 assert.equal(result.status,0,'Generated Ruby execution failed; never substitute source-only proof');
 return JSON.parse(result.stdout) as Array<Record<string,unknown>>;
}
test('H3 authored positive and negative corpus validates and compiles all eight reviewed grammar formats',()=>{
 assert.equal(CORPUS.length,8);
 assert.equal(new Set(CORPUS.map(x=>x.format)).size,8);
 for(const family of [false,true])for(const item of CORPUS){
   const checked=validateProject(project(item,family));
   assert.equal(checked.ok,true,item.format+' '+JSON.stringify(checked.issues));
   const files=compilePair(project(item,family));
   assert.equal(files.files.length,2);
   assert.equal(sha(item.good).length,64);
   if(item.format!=='regex')
     assert.ok(Buffer.byteLength(item.good,'utf8')>item.good.length,
       'H3 must account for Unicode byte lengths '+item.format);
 }
 if(required)assert.equal(available,true,
   'Native CI must not skip cross-grammar independent golden execution');
});
test('H3 generated native 8-grammar differential has exact typed, error-stage and raw-leak truth',
 {skip:!available},()=>{
 for(const family of [false,true])for(const item of CORPUS){
   const input=[item.good,item.bad];
   const outputs=native(project(item,family),input);
   assert.equal(outputs.length,2,item.format+' missing/fabricated native events');
   const good=outputs[0]!,bad=outputs[1]!;
   assert.equal(good.srcip,item.expectedIp,item.format+' official srcip');
   assert.equal(good.action,item.expectedAction,item.format+' official action');
   assert.equal(good.stellar_log_index,item.expectedAction==='deny'?'threat':'syslog',
     item.format+' official routing');
   assert.equal(good.parser_err_stage,undefined,item.format+' successful native diagnostics');
   assert.equal(bad.parser_err_stage,'normalization',item.format+' error stage');
   assert.equal(bad.parser_err_field,item.srcField,item.format+' error field');
   assert.equal(bad.parser_err_msg,'MappedFieldError',item.format+' error code');
   assert.equal(bad.stellar_log_index,'syslog',item.format+' no false positive index');
   assert.equal(bad.action,item.expectedAction,item.format+' unrelated action preserved');
   assert.ok(!Object.hasOwn(bad,'srcip'),item.format+' invalid official IP leaked');
   for(const record of outputs){
     const serialized=JSON.stringify(record);
     for(const source of input)
       assert.ok(!serialized.includes(source),item.format+' raw log leak');
   }
 }
});
