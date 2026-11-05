import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {recipeFromLegacyProject,validateRecipePair} from '../src/parser-recipe-v02.js';
import {sampleProject} from './fixture.js';
import type {FieldRule,ParserProject} from '../src/types.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const int=(name:string):FieldRule=>({normalized_name:name,data_type:'integer'});
const str=(name:string):FieldRule=>({normalized_name:name,data_type:'string'});
const ip=(name:string):FieldRule=>({normalized_name:name,data_type:'ip'});
const date=(name:string):FieldRule=>({normalized_name:name,data_type:'date',time_format:'iso8601',timezone:'UTC'});

function fixture(fields:Record<string,FieldRule>,family:boolean,options?:{
 enrichment?:ParserProject['enrichment'];vendorFields?:Record<string,FieldRule>;
 receiver?:Partial<ParserProject['receiver']>;
}):ParserProject{
 const p=sampleProject();
 p.normalization.topFields=fields;
 p.normalization.vendorFields=family?{}:(options?.vendorFields??{});
 p.normalization.nsFields={};
 p.enrichment=options?.enrichment??[];
 p.classification.rules=[];
 p.receiver={...p.receiver,...options?.receiver};
 if(family){
  p.normalization.topFields={event_type:str('event_type')};
  p.normalization.eventProfiles={
   discriminator:'event_type',unknown:'reject',variants:[
    {name:'security',equals:'security',topFields:fields,nsFields:{},vendorFields:options?.vendorFields??{}},
    {name:'other',equals:'other',topFields:{username:str('username')},nsFields:{},vendorFields:{}},
   ],
  };
 }
 const verdict=validateProject(p);
 assert.equal(verdict.ok,true,JSON.stringify(verdict.issues));
 return p;
}

function native(p:ParserProject,inputs:string[]):Record<string,unknown>[]{
 const ruby=compilePair(p).files.find(f=>!f.name.endsWith('.conf'))!.content;
 const code=[
  "require 'json'","require 'base64'","require 'time'","require 'ipaddr'","require 'csv'",
  'klass=Class.new',
  "klass.class_eval(Base64.strict_decode64('"+Buffer.from(ruby).toString('base64')+"'))",
  'parser=klass.new',
  'results=[]',
  'JSON.parse(STDIN.read).each{|line|parser.parse(line){|_time,event|results << event}}',
  'STDOUT.write(JSON.generate(results))',
 ].join('\n');
 const raws=inputs.map(raw=>p.normalization.eventProfiles?
  raw.replace(/^\{/,'{"event_type":"security",'):raw);
 const response=spawnSync('ruby',['-e',code],{input:JSON.stringify(raws),
  encoding:'utf8',timeout:15000,maxBuffer:4*1024*1024});
 assert.equal(response.status,0,response.stderr||String(response.error));
 const actual=JSON.parse(response.stdout) as Record<string,unknown>[];
 assert.equal(actual.length,inputs.length);
 return actual;
}

for(const family of [false,true]){
 const label=family?'conditional-family':'single-family';
 test('F-01 '+label+' enriched official fields and protocol pair fail closed',{skip:!rubyAvailable},()=>{
  const badPair=fixture({p:int('proto')},family,{enrichment:[
   {operator:'set_const',target:'proto_name',value:'UDP'},
  ]});
  const pair=native(badPair,['{"p":6}'])[0]!;
  assert.equal(pair.parser_err_stage,'enrichment');
  assert.ok(!('proto_name' in pair));
  for(const [target,value] of [['srcip','not-an-ip'],
   ['timestamp','2026-02-30T00:00:00Z']] as const){
   const bad=fixture({action:str('action')},family,{enrichment:[
    {operator:'set_const',target,value},
   ]});
   const result=native(bad,['{"action":"deny"}'])[0]!;
   assert.equal(result.parser_err_stage,'enrichment',target);
   assert.ok(!(target in result));
  }
  // Codex PR review: ISO set_const must stay text during subsequent string
  // operations, then become epoch milliseconds in the emitted native record.
  const chained=fixture({action:str('action')},family,{enrichment:[
    {operator:'set_const',target:'timestamp',value:'2026-11-04T12:00:00Z'},
    {operator:'uppercase',source:'timestamp',target:'message'},
    {operator:'copy',source:'timestamp',target:'custom.reviewed_timestamp'},
  ]});
  const chainedOutput=native(chained,['{"action":"deny"}'])[0]!;
  assert.equal(chainedOutput.parser_err_stage,undefined);
  assert.equal(chainedOutput.message,'2026-11-04T12:00:00Z');
  assert.equal((chainedOutput.custom as Record<string,unknown>)?.reviewed_timestamp,
    '2026-11-04T12:00:00Z');
  assert.equal(chainedOutput.timestamp,Date.parse('2026-11-04T12:00:00Z'));
  const good=fixture({src:ip('srcip')},family,{enrichment:[
   family?{operator:'set_const',target:'dstip',value:'192.0.2.10'}:
    {operator:'copy',source:'srcip',target:'dstip'},
  ]});
  const output=native(good,['{"src":"192.0.2.10"}'])[0]!;
  assert.equal(output.srcip,'192.0.2.10');
  assert.equal(output.dstip,'192.0.2.10');
 });
 test('F-02/F-03 '+label+' JSON depth and unpaired surrogate parity',{skip:!rubyAvailable},()=>{
  const p=fixture({action:str('action')},family);
  const nested=(depth:number)=>{
   let value:unknown='leaf';
   for(let i=0;i<depth;i++)value={level:value};
   return JSON.stringify({action:'deny',payload:value});
  };
  const raws=[nested(6),nested(8),nested(12),
    '{"action":"deny","value":"\\ud800"}',
    '{"action":"deny","bad\\ud800":1}',
    '{"action":"deny","value":"\\udc00"}',
    '{"action":"deny","value":"\\ud83d\\ude02"}'];
  const result=native(p,raws);
  assert.equal(result[0]?.action,'deny');
  for(let i=1;i<=5;i++)
    assert.equal(result[i]?.parser_err_stage,'extraction',JSON.stringify({i,record:result[i]}));
  assert.equal(result[6]?.action,'deny');
 });
 test('F-06/F-07 '+label+' receiver byte budget and lone CR boundaries',{skip:!rubyAvailable},()=>{
  const p=fixture({action:str('action')},family);
  p.receiver.messageLengthLimit=8192;
  const raws=[
    JSON.stringify({action:'deny',payload:'a'.repeat(7900)}),
    JSON.stringify({action:'deny',payload:'a'.repeat(8200)}),
    JSON.stringify({action:'deny',payload:'한'.repeat(2600)}),
    JSON.stringify({action:'deny',payload:'한'.repeat(2900)}),
    '{"action":"deny"}\r{"action":"allow"}',
  ];
  const result=native(p,raws);
  assert.equal(result[0]?.action,'deny');
  assert.equal(result[2]?.action,'deny');
  for(const i of [1,3,4])assert.equal(result[i]?.parser_err_stage,'extraction');
 });
 test('F-09/F-10 '+label+' integral JSON tokens and strict IP literals',{skip:!rubyAvailable},()=>{
  const p=fixture({p:int('proto'),port:{normalized_name:'dstport',data_type:'port'},
   src:ip('srcip')},family);
  const raws=[
   '{"p":6.0,"port":443.0,"src":"192.0.2.1"}',
   '{"p":6e0,"port":443,"src":"2001:db8::1"}',
   '{"p":6.5,"port":443,"src":"192.0.2.1"}',
   '{"p":6,"port":443,"src":"192.0.2.1/24"}',
   '{"p":6,"port":443,"src":"2001:db8::1/64"}',
   '{"p":6,"port":443,"src":"fe80::1%eth0"}',
  ];
  const result=native(p,raws);
  assert.equal(result[0]?.proto,6);
  assert.equal(result[0]?.dstport,443);
  assert.equal(result[1]?.proto,6);
  for(let i=2;i<6;i++)assert.equal(result[i]?.parser_err_stage,'normalization',raws[i]);
  const v=fixture({},family,{vendorFields:{flag:{normalized_name:'custom.flag',data_type:'boolean'}}});
  const bools=native(v,['{"flag":1.0}','{"flag":1e0}','{"flag":0.5}']);
  assert.equal(((bools[0] as any).Synthetic?.custom?.flag),true);
  assert.equal(((bools[1] as any).Synthetic?.custom?.flag),true);
  assert.equal(bools[2]?.parser_err_stage,'normalization');
 });
 test('F-11 '+label+' strict timestamp offset and second 60',{skip:!rubyAvailable},()=>{
  const p=fixture({ts:date('timestamp')},family);
  const cases=['2026-11-04T00:00:00Z','2026-11-04T00:00:00+14:00',
    '2026-11-04T00:00:00+00:60','2026-11-04T00:00:00+12:60',
    '2026-11-04T23:59:60Z','2026-02-30T12:00:00Z',
    '2024-02-29T23:59:59Z'];
  const results=native(p,cases.map(ts=>JSON.stringify({ts})));
  assert.equal(results[0]?.timestamp,Date.parse(cases[0]!));
  assert.equal(results[1]?.timestamp,Date.parse(cases[1]!));
  for(let i=2;i<=5;i++)assert.equal(results[i]?.parser_err_stage,'normalization');
  assert.equal(results[6]?.timestamp,Date.parse(cases[6]!));
 });
 test('F-04 '+label+' byte-identical JSON object-to-string coercion',{skip:!rubyAvailable},()=>{
  const p=fixture({},family,{vendorFields:{details:str('custom.payload')}});
  const raw='{"details":{"2":"b","1":"a","small":0.000001,"float":1.0,"large":1e21,"arr":[0.0000001,true,"한"]}}';
  const result=native(p,[raw])[0]!;
  assert.equal(result.parser_err_stage,undefined);
  const expected=JSON.stringify((JSON.parse(raw) as {details:unknown}).details);
  assert.equal((result.Synthetic as any)?.custom?.payload,expected);
 });
 test('F-05 '+label+' ECS root selector keeps v0.2 recipe identity',{skip:!rubyAvailable},()=>{
  const p=fixture({'@timestamp':{...date('timestamp'),source_path_kind:'literal_root'}},family);
  if(!family){
   p.projectId='draft-synthetic_recipe';
   const recipe=recipeFromLegacyProject(p,'a'.repeat(64),1);
   assert.equal(validateRecipePair({recipe,legacyProject:p}).ok,true);
  }
  const result=native(p,['{"@timestamp":"2026-11-04T12:00:00Z"}'])[0]!;
  assert.equal(result.timestamp,Date.parse('2026-11-04T12:00:00Z'));
 });
 test('F-08 '+label+' native accepts deliberate TCP LF LF multiline JSON',{skip:!rubyAvailable},()=>{
  const p=fixture({action:str('action')},family,{receiver:{
   protocols:['tcp'],tcpFraming:'blank_line_json',
  }});
  const raw='{\n"action":"deny",\n"srcip":"192.0.2.1"\n}';
  const result=native(p,[raw])[0]!;
  assert.equal(result.action,'deny');
 });
}
