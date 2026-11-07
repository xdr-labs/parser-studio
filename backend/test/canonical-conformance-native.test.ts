import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {compilePair} from '../src/compiler.js';
import {validateBoundedRegexPattern,validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import type {ParserProject} from '../src/types.js';

const corpus=JSON.parse(readFileSync(
  new URL('../../contracts/conformance-cases.v1.json',import.meta.url),'utf8')) as {
  contract:string;
  kvWhitespace:Array<{
    id:string;trailer:string;quoted:boolean;internal?:string;srcip?:string;accept:boolean;
  }>;
  regexSafety:Array<{id:string;pattern:string;accept:boolean}>;
};
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const rubyRequired=process.env.PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED==='1';

function fixtureProject():ParserProject{
  const p=sampleProject();
  p.receiver.port=6801;
  p.projectId='canonical_conformance_kv';
  p.slug='canonical_kv';
  p.extraction={format:'kv'};
  p.normalization.topFields={
    action:{normalized_name:'action',data_type:'string'},
    srcip:{normalized_name:'srcip',data_type:'ip'},
  };
  p.normalization.nsFields={};
  p.normalization.vendorFields={};
  p.classification.rules=[];
  assert.deepEqual(validateProject(p),{ok:true,issues:[]});
  return p;
}
function nativeSource(ruby:string,inputs:string[]):Array<Record<string,unknown>>{
  const runner=[
    "require 'json'","require 'base64'","require 'time'","require 'date'",
    "require 'ipaddr'","require 'csv'",
    "input=JSON.parse(STDIN.read)","klass=Class.new",
    "klass.class_eval(Base64.strict_decode64(input.fetch('ruby')),'canonical-native',1)",
    "parser=klass.new","rows=[]",
    "input.fetch('inputs').each{|line|parser.parse(line){|_time,record|rows << record}}",
    "STDOUT.write(JSON.generate(rows))",
  ].join('\n');
  const result=spawnSync('ruby',['-e',runner],{
    encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
    input:JSON.stringify({ruby:Buffer.from(ruby).toString('base64'),inputs}),
  });
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout) as Array<Record<string,unknown>>;
}
const input=(x:typeof corpus.kvWhitespace[number]):string=>
  'action=allow srcip='+
    (x.quoted?'"'+(x.internal??'192.0.2.1')+'"':'192.0.2.1')+x.trailer;

test('Canonical contract enforces an executable native runtime when CI requires it',()=>{
  assert.equal(corpus.contract,'parser-studio.cross-engine-corpus.v1');
  if(rubyRequired)assert.equal(rubyAvailable,true,
    'Ruby must be installed for mandatory same-head generated-parser conformance');
});
test('Canonical regex safety corpus agrees with backend authoring validation',()=>{
  for(const item of corpus.regexSafety){
    assert.equal(validateBoundedRegexPattern(item.pattern)===null,item.accept,item.id);
  }
});
test('Generated Ruby DRAFT agrees with KV Unicode source/error golden cases',
  {skip:!rubyAvailable},()=>{
    const pair=compilePair(fixtureProject());
    assert.equal(pair.manifest.status,'DRAFT');
    const source=pair.files.find(file=>!file.name.endsWith('.conf'))!.content;
    const rows=nativeSource(source,corpus.kvWhitespace.map(input));
    assert.equal(rows.length,corpus.kvWhitespace.length);
    for(let i=0;i<corpus.kvWhitespace.length;i++){
      const item=corpus.kvWhitespace[i]!;
      const row=rows[i]!;
      const stage=row.parser_err_stage;
      const good=item.srcip==='192.0.2.1';
      if(good){
        assert.equal(stage,undefined,item.id+' '+JSON.stringify(row));
        assert.equal(row.srcip,'192.0.2.1',item.id);
      }else if(item.quoted&&item.trailer){
        assert.equal(stage,'extraction',item.id+' '+JSON.stringify(row));
        assert.equal(row.srcip,undefined,item.id);
      }else{
        assert.equal(stage,'normalization',item.id+' '+JSON.stringify(row));
        assert.equal(row.srcip,undefined,item.id);
        assert.equal(row.parser_err_field,'srcip',item.id);
        assert.equal(row.action,'allow',item.id);
      }
    }
  });
test('Both native Ruby templates have identical strict KV Unicode grammar',
  {skip:!rubyAvailable},()=>{
    const source=[
      "require 'json'","require 'base64'","require 'ipaddr'","require 'csv'","require 'time'",
      "k=Class.new;k.class_eval(Base64.strict_decode64(STDIN.gets.strip))",
      "parser=k.allocate","rows=[]",
      "JSON.parse(STDIN.read).each do |line|",
      "begin;rows << {'ok'=>true,'fields'=>parser.parserstudio_key_values(line)}",
      "rescue StandardError;rows << {'ok'=>false};end;end",
      "STDOUT.write(JSON.generate(rows))",
    ].join('\n');
    const raw=corpus.kvWhitespace.map(input);
    const signatures:string[]=[];
    for(const name of ['ruby-fragment.rb.tpl','ruby-forwarder-family.rb.tpl']){
      const template=readFileSync(new URL('../templates/'+name,import.meta.url),'utf8');
      const out=spawnSync('ruby',['-e',source],{
        encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
        input:Buffer.from(template).toString('base64')+'\n'+JSON.stringify(raw),
      });
      assert.equal(out.status,0,name+' '+out.stderr);
      const rows=JSON.parse(out.stdout) as Array<{ok:boolean;fields?:Record<string,unknown>}>;
      for(let i=0;i<rows.length;i++){
        const item=corpus.kvWhitespace[i]!;
        const row=rows[i]!;
        if(item.quoted&&item.trailer)assert.equal(row.ok,false,item.id);
        else{
          assert.equal(row.ok,true,item.id);
          assert.equal(row.fields?.srcip,item.srcip,item.id);
        }
      }
      signatures.push(JSON.stringify(rows));
    }
    assert.equal(signatures[0],signatures[1],'Generated Ruby templates must agree');
  });
