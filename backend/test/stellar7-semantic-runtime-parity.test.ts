import {resolvedTemplate} from './template-fixture.js';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';

const oldStyle=resolvedTemplate('ruby-fragment.rb.tpl');
const familyStyle=resolvedTemplate('ruby-forwarder-family.rb.tpl');
const helper=(source:string)=>{
  const begin=source.indexOf('def parserstudio_stellar7_value_valid?(');
  assert.ok(begin>=0,'Missing official-field semantic validator');
  const end=source.indexOf('\nend\n',begin);
  assert.ok(end>begin);
  return source.slice(begin,end+5);
};

// Browser semantics, single-type Ruby and conditional-family Ruby must all
// reject invalid official scalar values instead of certifying normalization.
test('both native DRAFT templates enforce the same official 7.0 destination value contract',()=>{
  const first=helper(oldStyle);
  assert.equal(first,helper(familyStyle));
  for(const field of ['dstport','srcport','severity','sha256','sha1','md5','action'])
    assert.ok(first.includes(field),'Missing official constraint '+field);
  assert.ok(oldStyle.includes("section != 'vendorFields' && !parserstudio_stellar7_value_valid?"));
  assert.ok(familyStyle.includes("section != 'vendorFields' && !parserstudio_stellar7_value_valid?"));
});

function project(target:string,type:'integer'|'string',family=false,vendor=false){
  const p=sampleProject();
  p.normalization.topFields={};p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[];
  const mapping={value:{normalized_name:target,data_type:type}};
  if(family){
    p.normalization.topFields={event_type:{normalized_name:'event_type',data_type:'string'}};
    p.normalization.eventProfiles={discriminator:'event_type',unknown:'reject',variants:[
      {name:'threat',equals:'threat',topFields:mapping,nsFields:{},vendorFields:{}},
      {name:'user',equals:'user',
        topFields:{username:{normalized_name:'username',data_type:'string'}},
        nsFields:{},vendorFields:{}},
    ]};
  }else if(vendor)p.normalization.vendorFields=mapping;
  else p.normalization.topFields=mapping;
  return p;
}

test('conditional native fixture has two explicit independent event-family variants',()=>{
  assert.equal(validateProject(project('sha256','string',true)).ok,true);
});

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
function execute(target:string,type:'integer'|'string',value:unknown,family=false,vendor=false){
  const p=project(target,type,family,vendor);
  const code=compilePair(p).files.find(file=>!file.name.endsWith('.conf'))!.content;
  assert.ok(code.includes('parserstudio_stellar7_value_valid?'));
  const program=[
    "require 'json'","require 'base64'","require 'csv'","require 'time'","require 'ipaddr'",
    'klass = Class.new',
    "klass.class_eval(Base64.strict_decode64('"+Buffer.from(code).toString('base64')+"'))",
    'parser = klass.new',
    'parser.parse(STDIN.read){|_time,record| puts JSON.generate(record)}',
  ].join('\n');
  const source=JSON.stringify(family?{event_type:'threat',value}:{value});
  const result=spawnSync('ruby',['-e',program],{
    encoding:'utf8',input:source,timeout:15000,maxBuffer:1024*1024,
  });
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout) as Record<string,unknown>;
}

for(const [target,type,invalid,valid] of [
  ['dstport','integer',65536,65535],['srcport','integer',-1,0],
  ['severity','integer',101,100],
  ['sha256','string','a'.repeat(32),'a'.repeat(64)],
  ['file.hash.md5','string','a'.repeat(40),'a'.repeat(32)],
  ['action','string',200,'block'],
] as const){
  test(`native mainline rejects invalid ${target}, but accepts valid values`,
    {skip:!rubyAvailable},()=>{
      const bad=execute(target,type,invalid);
      assert.equal(bad.parser_err_stage,'normalization');
      assert.equal(bad.parser_err_field,'value');
      assert.equal(bad.parser_err_msg,'MappedFieldError');
      assert.ok(!JSON.stringify(bad).includes(String(invalid)));
      const good=execute(target,type,valid);
      assert.ok(!('parser_err_stage' in good));
    });
}
test('conditional type-specific native DRAFT has the same hash constraint',
  {skip:!rubyAvailable},()=>{
    const bad=execute('sha256','string','a'.repeat(32),true);
    assert.equal(bad.parser_err_stage,'normalization');
    assert.equal(bad.parser_err_field,'value');
    const good=execute('sha256','string','a'.repeat(64),true);
    assert.equal(good.sha256,'a'.repeat(64));
  });
test('native vendor-local mapping remains unqualified and unmodified',
  {skip:!rubyAvailable},()=>{
    const local=execute('sha256','string','not-an-official-hash',false,true);
    assert.equal((local.Synthetic as Record<string,unknown>).sha256,'not-an-official-hash');
    assert.ok(!('parser_err_stage' in local));
  });
