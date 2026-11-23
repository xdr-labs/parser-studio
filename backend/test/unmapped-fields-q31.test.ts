import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdirSync,writeFileSync} from 'node:fs';
import test from 'node:test';
import {rubyE} from './ruby-argv.js';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {READING_FAMILY_DISCRIMINATOR} from '../src/canonical-operator-contract.js';
import {sampleProject} from './fixture.js';
import type {ParserProject} from '../src/types.js';

// Owner decision Q3-1 (2026-11-24): the generated Ruby keeps every extracted field no mapping reads in the vendor
// namespace, as the browser does (src/unmappedFields.ts). SYNTHETIC lines. With Q31_RB_DIR set, the compiled
// parsers are also written there for the Ruby 2.4.9 runner.
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const map=(entries:Record<string,[string,string]>)=>Object.fromEntries(Object.entries(entries)
  .map(([source,[name,type]])=>[source,{normalized_name:name,data_type:type}])) as ParserProject['normalization']['topFields'];
function project(format:ParserProject['extraction'],top:Record<string,[string,string]>,vendor:Record<string,[string,string]>,
  preserve=true):ParserProject{
  const p=sampleProject();
  p.extraction=format;
  p.normalization.topFields=map(top);p.normalization.nsFields={};p.normalization.vendorFields=map(vendor);
  if(preserve)p.normalization.preserveUnmapped=true;
  p.classification.rules=[];
  return p;
}
function run(name:string,p:ParserProject,lines:string[]):Record<string,unknown>[]{
  assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p).issues));
  const code=compilePair(p).files.find(f=>!f.name.endsWith('.conf'))!.content;
  if(process.env.Q31_RB_DIR){
    mkdirSync(process.env.Q31_RB_DIR,{recursive:true});
    writeFileSync(process.env.Q31_RB_DIR+'/'+name+'.rb',code);
    writeFileSync(process.env.Q31_RB_DIR+'/'+name+'.lines',lines.join('\n')+'\n');
  }
  const program=["require 'json'","require 'base64'","require 'time'","require 'ipaddr'",'klass = Class.new',
    "klass.class_eval(Base64.strict_decode64('"+Buffer.from(code).toString('base64')+"'))",'parser = klass.new',
    'STDIN.read.split("\\n").each { |line| parser.parse(line) { |_time, record| puts JSON.generate(record) } }'].join('\n');
  const result=spawnSync('ruby',rubyE(program),{encoding:'utf8',input:lines.join('\n'),timeout:30000,maxBuffer:4*1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return result.stdout.trim().split('\n').map(line=>JSON.parse(line) as Record<string,unknown>);
}

test('key=value: a key the sample never showed is kept in the vendor namespace',{skip:!rubyAvailable},()=>{
  const p=project({format:'kv'},{srcip:['srcip','ip'],dstip:['dstip','ip']},{action:['action','string']});
  const [out]=run('kv',p,['srcip=10.1.1.5 dstip=10.2.2.6 action=allow newkey=zzz note="a b=c"']);
  assert.equal(out!.srcip,'10.1.1.5');
  assert.deepEqual(out!.Synthetic,{action:'allow',newkey:'zzz',note:'a b=c'});
  assert.equal(out!.parser_err_msg,undefined);
});

test('JSON: nested, arrays, numbers, booleans, non-ASCII and a name a mapped vendor field holds',{skip:!rubyAvailable},()=>{
  const p=project({format:'json'},{srcip:['srcip','ip']},{'a.user':['user','string']});
  const [out]=run('json',p,['{"srcip":"10.1.1.3","a":{"user":"x3"},"user":"y3","tags":["a","b"],"geo":{"city":"서울","zip":"04524"},'+
    '"n":1.0,"big":1e2,"ok":true,"사용자":"김민수","msg":"a=b \\"q\\" \\\\ ü","dash":"-","nil":null}']);
  assert.equal(out!.srcip,'10.1.1.3');
  assert.deepEqual(out!.Synthetic,{user:'x3',parserstudio_unmapped:{user:'y3'},tags:'["a","b"]',
    geo:{city:'서울',zip:'04524'},n:'1',big:'100',ok:'true','사용자':'김민수',msg:'a=b "q" \\ ü'});
});

test('without the decision the generated parser is unchanged',{skip:!rubyAvailable},()=>{
  const p=project({format:'kv'},{srcip:['srcip','ip']},{},false);
  const [out]=run('kv_legacy',p,['srcip=10.1.1.5 newkey=zzz']);
  assert.equal(out!.Synthetic,undefined);
});

test('RFC 5424 key=value: a body key named like a header field is a field of its own',{skip:!rubyAvailable},()=>{
  const p=project({format:'syslog_rfc5424',syslogBodyFormat:'kv'},
    {syslog_hostname:['hostname','string'],'body.srcip':['srcip','ip']},{'body.action':['action','string']});
  const [out]=run('rfc5424',p,['<14>1 2026-10-12T01:02:05Z host5 app 1 - - srcip=10.1.1.3 action=allow syslog_hostname=inner7 port=22']);
  assert.equal(out!.hostname,'host5');
  const vendor=out!.Synthetic as Record<string,unknown>;
  assert.equal(vendor.action,'allow');
  assert.deepEqual(vendor.body,{syslog_hostname:'inner7',port:'22'});
  assert.equal(vendor.syslog_pri,'14');
});

test('mixed routed by reading family: each family keeps the keys of the other family',{skip:!rubyAvailable},()=>{
  const p=project({format:'mixed',mixedFormats:['json','kv']},{},{});
  p.normalization.eventProfiles={discriminator:READING_FAMILY_DISCRIMINATOR,unknown:'reject',variants:[
    {name:'json',equals:'json',nsFields:{},vendorFields:{},topFields:map({srcip:['srcip','ip']})},
    {name:'kv',equals:'kv',nsFields:{},vendorFields:map({user:['user','string']}),topFields:map({src:['srcip','ip']})},
  ]} as ParserProject['normalization']['eventProfiles'];
  const out=run('mixed',p,['{"srcip":"10.1.1.1","user":"alice","sport":"2001"}','src=10.5.5.6 user=bob srcip=10.9.9.9']);
  assert.equal(out[0]!.srcip,'10.1.1.1');
  assert.deepEqual(out[0]!.Synthetic,{user:'alice',sport:'2001'});
  assert.equal(out[1]!.srcip,'10.5.5.6');
  assert.deepEqual(out[1]!.Synthetic,{user:'bob',srcip:'10.9.9.9'});
});
