import assert from 'node:assert/strict';
import test from 'node:test';
import {spawnSync} from 'node:child_process';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import type {ParserProject} from '../src/types.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function project(extraction:'json'|'kv',family=false):ParserProject{
  const p=sampleProject();
  p.vendor='Acme';
  p.extraction={format:extraction};
  p.normalization.topFields={};
  p.normalization.nsFields={};
  p.normalization.vendorFields=extraction==='json'
    ?{session_id:{normalized_name:'custom.session_id_text',data_type:'string'}}
    :{field000:{normalized_name:'custom.sample',data_type:'string'}};
  p.classification.rules=[];
  if(family)p.normalization.eventProfiles={
    discriminator:'action',unknown:'reject',
    variants:[
      {name:'allowed',equals:'allow',topFields:{},nsFields:{},vendorFields:{}},
      {name:'denied',equals:'deny',topFields:{},nsFields:{},vendorFields:{}},
    ],
  };
  assert.deepEqual(validateProject(p),{ok:true,issues:[]});
  return p;
}
function native(p:ParserProject,lines:string[]):Record<string,any>[]{
  const pair=compilePair(p);
  assert.equal(pair.manifest.status,'DRAFT');
  const ruby=pair.files.find(file=>!file.name.endsWith('.conf'))!.content;
  const code=[
    "require 'json'","require 'base64'","require 'time'","require 'date'",
    "require 'ipaddr'","require 'csv'",
    'input=JSON.parse(STDIN.read)','klass=Class.new',
    "klass.class_eval(Base64.strict_decode64(input.fetch('ruby')))",
    'parser=klass.new','result=[]',
    "input.fetch('lines').each{|line|parser.parse(line){|_time,record|result << record}}",
    'STDOUT.write(JSON.generate(result))',
  ].join('\n');
  const out=spawnSync('ruby',['-e',code],{
    input:JSON.stringify({ruby:Buffer.from(ruby).toString('base64'),lines}),
    timeout:15000,maxBuffer:1024*1024,encoding:'utf8',
  });
  assert.equal(out.status,0,out.stderr||String(out.error));
  return JSON.parse(out.stdout) as Record<string,any>[];
}

test('Audit #236: backend rejects protected runtime diagnostics and vendor namespace',()=>{
  for(const target of ['parser_err_stage','parser_err_field','parser_err_msg',
    'parserstudio_source','parserstudio_transport','parserstudio_event_family',
    'msg_origin','stellar_log_index']){
    const p=sampleProject();
    p.normalization.topFields={action:{normalized_name:target,data_type:'string'}};
    p.normalization.nsFields={};
    p.normalization.vendorFields={};
    p.classification.rules=[];
    assert.equal(validateProject(p).ok,false,target);
  }
  for(const vendor of ['parserstudio_source','parserstudio_transport','parser_err_stage',
    'parser_err_field','stellar_log_index']){
    const p=project('json');
    p.vendor=vendor;
    assert.ok(validateProject(p).issues.some(item=>item.code==='reserved_vendor_namespace'),vendor);
  }
  const p=project('json');
  p.vendor='Acme';
  assert.equal(validateProject(p).ok,true);
});

test('Audit #237: generated Ruby contains lexical JSON precision guards in both templates',()=>{
  for(const family of [false,true]){
    const ruby=compilePair(project('json',family)).files.find(file=>!file.name.endsWith('.conf'))!.content;
    assert.match(ruby,/def parserstudio_json_unsafe_number\?\(raw\)/);
    assert.match(ruby,/Unsafe JSON numeric precision/);
  }
});

for(const family of [false,true]){
  test('Audit #237: '+(family?'event-family':'standard')+
       ' native JSON numeric safety matches browser review',{skip:!rubyAvailable},()=>{
    const rows=native(project('json',family),[
      '{"action":"allow","session_id":"9007199254740993"}',
      '{"action":"allow","session_id":9007199254740993}',
      '{"action":"allow","session_id":9.007199254740993e15}',
      '{"action":"allow","session_id":0.1234567890123456789}',
      '{"action":"allow","session_id":1e309}',
      '{"action":"allow","session_id":1e-999}',
      '{"action":"allow","session_id":17}',
      '{"action":"allow","session_id":1e-6}',
      '{"action":"allow","session_id":"quoted \\"9007199254740993\\""}',
    ]);
    assert.equal(rows.length,9);
    assert.equal(rows[0]?.Acme?.custom?.session_id_text,'9007199254740993');
    for(const index of [1,2,3,4,5])
      assert.equal(rows[index]?.parser_err_stage,'extraction',JSON.stringify({index,row:rows[index]}));
    assert.equal(rows[6]?.parser_err_stage,undefined);
    assert.equal(rows[7]?.parser_err_stage,undefined);
    assert.equal(rows[8]?.Acme?.custom?.session_id_text,'quoted "9007199254740993"');
  });
}

test('Audit #238: native KV rejects key 101 but preserves 100-key event',{skip:!rubyAvailable},()=>{
  const mk=(count:number)=>Array.from({length:count},
    (_,i)=>'field'+String(i).padStart(3,'0')+'=v').join(' ');
  const rows=native(project('kv'),[mk(99),mk(100),mk(101)]);
  assert.equal(rows.length,3);
  assert.equal(rows[0]?.parser_err_stage,undefined);
  assert.equal(rows[1]?.parser_err_stage,undefined);
  assert.equal(rows[2]?.parser_err_stage,'extraction');
});
