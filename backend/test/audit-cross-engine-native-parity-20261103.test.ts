import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';

const rubyBin=process.env.PARSER_RUBY_BIN||'ruby';
const available=spawnSync(rubyBin,['-v'],{encoding:'utf8'}).status===0;
const slash=String.fromCharCode(92);
const winPath='C:'+slash+'Windows'+slash+'System32'+slash+'cmd.exe';
const kv='path="'+winPath+'" action=deny';

function execute(source:string,raw:string,extractor:'kv'|'syslog_rfc5424'|'syslog_rfc3164'|'leef'|'parse'){
  const runner=[
    "require 'json'","require 'base64'","require 'ipaddr'","require 'csv'","require 'time'",
    'input=JSON.parse(STDIN.read)',
    'klass=Class.new',
    "klass.class_eval(Base64.strict_decode64(input.fetch('source')),'generated_audit',1)",
    "parser=input.fetch('extractor')=='parse' ? klass.new : klass.allocate",
    'begin',
    'record=nil',
    "case input.fetch('extractor')",
    "when 'kv' then record=parser.parserstudio_key_values(input.fetch('raw'))",
    "when 'syslog_rfc5424' then record=parser.parserstudio_syslog_rfc5424(input.fetch('raw'),{'syslogBodyFormat'=>'kv'})",
    "when 'syslog_rfc3164' then record=parser.parserstudio_syslog_rfc3164(input.fetch('raw'),{'syslogBodyFormat'=>'kv'})",
    "when 'leef' then record=parser.parserstudio_leef(input.fetch('raw'))",
    "when 'parse' then parser.parse(input.fetch('raw')){|_time,value|record=value}",
    'end',
    "STDOUT.write(JSON.generate({'ok'=>true,'record'=>record}))",
    'rescue StandardError => error',
    "STDOUT.write(JSON.generate({'ok'=>false,'error'=>error.class.name}))",
    'end'
  ].join('\n');
  const result=spawnSync(rubyBin,['-e',runner],{
    input:JSON.stringify({source:Buffer.from(source).toString('base64'),raw,extractor}),
    encoding:'utf8',timeout:12000,maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout) as {ok:boolean;record?:Record<string,any>;error?:string};
}

test('both Ruby templates retain path separators across KV, RFC5424 and RFC3164',
  {skip:!available},()=>{
    for(const name of ['ruby-fragment.rb.tpl','ruby-forwarder-family.rb.tpl']){
      const template=readFileSync(new URL('../templates/'+name,import.meta.url),'utf8');
      for(const [extractor,raw] of [
        ['kv',kv],
        ['syslog_rfc5424','<14>1 2026-11-03T11:11:11Z fw app - ID - '+kv],
        ['syslog_rfc3164','<134>May 5 17:51:17 edge01 app: '+kv],
      ] as const){
        const result=execute(template,raw,extractor);
        assert.equal(result.ok,true,name+' '+extractor);
        const got=extractor==='kv'?result.record?.path:result.record?.body?.path;
        assert.equal(got,winPath,name+' '+extractor);
      }
      const quote=execute(template,"note='we"+slash+"'re okay' escape=\"a"+slash+"=b\" action=deny",'kv');
      assert.equal(quote.record?.note,"we're okay");
      assert.equal(quote.record?.escape,'a=b');
      const doubled=execute(template,'path="C:'+slash+slash+'Windows'+slash+slash+'cmd.exe"','kv');
      assert.equal(doubled.record?.path,'C:'+slash+'Windows'+slash+'cmd.exe');
      for(const raw of [
        'src=192.0.2.10 INVALID_FRAGMENT action=deny',
        'src=192.0.2.10 action=deny INVALID_TAIL',
        'src=192.0.2.10 __proto__=hidden',
      ])assert.equal(execute(template,raw,'kv').ok,false,name+' unsafe: '+raw);
      const leef='LEEF:2.0|Vendor|Product|1.0|ID|^|src=192.0.2.10^__proto__=hidden';
      assert.equal(execute(template,leef,'leef').ok,false,name+' unsafe LEEF');
    }
  });

test('actual compiled Ruby DRAFT preserves the original Windows path',
  {skip:!available},()=>{
    const project=sampleProject();
    project.projectId='audit-kv-lossless';
    project.slug='audit_kv_lossless';
    project.extraction={format:'kv'};
    project.normalization.topFields={action:{normalized_name:'action',data_type:'string'}};
    project.normalization.nsFields={};
    project.normalization.vendorFields={path:{normalized_name:'path',data_type:'string'}};
    project.classification.rules=[];
    assert.equal(validateProject(project).ok,true);
    const pair=compilePair(project);
    assert.equal(pair.manifest.status,'DRAFT');
    const code=pair.files.find(file=>!file.name.endsWith('.conf'))!.content;
    const result=execute(code,kv,'parse');
    assert.equal(result.ok,true);
    assert.equal(result.record?.Synthetic?.path,winPath);
    assert.equal(result.record?.parser_err_msg,undefined);
  });

test('generated Ruby DRAFT has exact Browser-approved port/IP conversion', {skip:!available},()=>{
    const project=sampleProject();
    project.projectId='audit-native-typed-coercion';
    project.slug='audit_native_typed_coercion';
    project.extraction={format:'kv'};
    project.normalization.topFields={
      action:{normalized_name:'action',data_type:'string'},
      src_ip:{normalized_name:'srcip',data_type:'ip'},
      dst_port:{normalized_name:'dstport',data_type:'port'},
    };
    project.normalization.nsFields={};
    project.normalization.vendorFields={};
    project.classification.rules=[];
    assert.equal(validateProject(project).ok,true);
    const ruby=compilePair(project).files.find(file=>!file.name.endsWith('.conf'))!.content;
    const normal=execute(ruby,'action=deny src_ip=" 192.0.2.10 " dst_port=" 443 "','parse');
    assert.equal(normal.ok,true);
    assert.equal(normal.record?.parser_err_msg,undefined);
    assert.equal(normal.record?.srcip,'192.0.2.10');
    assert.equal(normal.record?.dstport,443);
    const signed=execute(ruby,'action=deny src_ip=192.0.2.10 dst_port="+443"','parse');
    assert.equal(signed.record?.parser_err_msg,'MappedFieldError');
    assert.equal(signed.record?.parser_err_field,'dst_port');
  });

test('both Ruby template scalar conversions agree on whitespace, sign and IPv6',
  {skip:!available},()=>{
    for(const name of ['ruby-fragment.rb.tpl','ruby-forwarder-family.rb.tpl']){
      const template=readFileSync(new URL('../templates/'+name,import.meta.url),'utf8');
      const ruby=[
        "require 'json'","require 'base64'","require 'ipaddr'","require 'csv'","require 'time'",
        "klass=Class.new",
        "klass.class_eval(Base64.strict_decode64(ARGV.fetch(0)))",
        "p=klass.allocate",
        "cases=[['port',' 443 '],['port','+443'],['integer',' 42 '],['integer','+42'],['boolean',' true '],['ip',' 192.0.2.10 '],['ip','2001:0db8::0001'],['date',' 2026-11-03T11:11:11Z ']]",
        "cases.each do |type,value|",
        "begin;rule={'data_type'=>type};rule['time_format']='iso8601' if type=='date';converted=p.parserstudio_coerce(value,rule);puts JSON.generate({'ok'=>true,'converted'=>converted})",
        "rescue;puts JSON.generate({'ok'=>false})",
        "end;end"
      ].join('\n');
      const result=spawnSync(rubyBin,['-e',ruby,Buffer.from(template).toString('base64')],{
        encoding:'utf8',timeout:12000,maxBuffer:1024*1024});
      assert.equal(result.status,0,result.stderr||String(result.error));
      const cases=result.stdout.trim().split('\n').map(line=>JSON.parse(line) as {ok:boolean;converted?:unknown});
      assert.deepEqual(cases.map(x=>x.ok),[true,false,true,false,true,true,true,true],name);
      assert.deepEqual(cases.slice(0,7).map(x=>x.converted),[
        443,undefined,42,undefined,true,'192.0.2.10','2001:0db8::0001'
      ],name);
    }
  });
