import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import type {ParserProject} from '../src/types.js';

const prefix='syslog_sd.element_1.params.';
const when={sourcePath:prefix+'protocol-id',operator:'in' as const,values:['6','17']};
const original=readFileSync(resolve('../tests/fixtures/docs-practice-20261104/01-juniper-srx.log'),'utf8').trim().split('\n');
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function project(withFamily=false):ParserProject{
  const p=sampleProject();
  p.projectId='draft_issue232_juniper_conditional';
  p.slug='issue232_juniper';
  p.receiver.port=6801;
  p.extraction={format:'syslog_rfc5424',syslogBodyFormat:'raw'};
  p.normalization.topFields={
    [prefix+'protocol-id']:{normalized_name:'proto',data_type:'integer'},
    [prefix+'source-port']:{normalized_name:'srcport',data_type:'integer',when},
    [prefix+'destination-port']:{normalized_name:'dstport',data_type:'integer',when},
  };
  p.normalization.nsFields={};
  p.normalization.vendorFields={
    [prefix+'source-port']:{normalized_name:'original_source_port',data_type:'string'},
    [prefix+'destination-port']:{normalized_name:'original_destination_port',data_type:'string'},
  };
  p.classification.rules=[];
  if(withFamily)p.normalization.eventProfiles={
    discriminator:'syslog_msgid',unknown:'reject',
    variants:[
      {name:'created',equals:'RT_FLOW_SESSION_CREATE',topFields:{},nsFields:{},vendorFields:{}},
      {name:'denied',equals:'RT_FLOW_SESSION_DENY',topFields:{},nsFields:{},vendorFields:{}},
    ],
  };
  return p;
}
function runNative(p:ParserProject,raw:string[]):Array<Record<string,any>>{
  const pair=compilePair(p);
  assert.equal(pair.manifest.status,'DRAFT');
  assert.equal(pair.manifest.targetImportVerified,false);
  const ruby=pair.files.find(f=>!f.name.endsWith('.conf'))?.content;
  assert.ok(ruby);
  const source=[
    "require 'json'","require 'base64'","require 'time'","require 'date'","require 'ipaddr'","require 'csv'",
    'input=JSON.parse(STDIN.read)','klass=Class.new',
    "klass.class_eval(Base64.strict_decode64(input.fetch('ruby')),'issue232_native',1)",
    'parser=klass.new','rows=[]',
    "input.fetch('lines').each{|line|parser.parse(line){|_time,record|rows << record}}",
    'STDOUT.write(JSON.generate(rows))',
  ].join('\n');
  const out=spawnSync('ruby',['-e',source],{
    encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
    input:JSON.stringify({ruby:Buffer.from(ruby).toString('base64'),lines:raw}),
  });
  assert.equal(out.status,0,out.stderr||String(out.error));
  return JSON.parse(out.stdout) as Array<Record<string,any>>;
}

test('Issue #232: backend rejects unsupported, unbounded or unsafe mapping predicates',()=>{
  const p=project();
  assert.deepEqual(validateProject(p),{ok:true,issues:[]});
  const copy=(x:unknown)=>JSON.parse(JSON.stringify(x)) as ParserProject;
  for(const bad of [
    {sourcePath:prefix+'protocol-id',operator:'eval',values:['6']},
    {sourcePath:prefix+'protocol-id',operator:'in',values:[]},
    {sourcePath:prefix+'protocol-id',operator:'in',values:['6','6']},
    {sourcePath:'__proto__.polluted',operator:'in',values:['6']},
    {sourcePath:prefix+'protocol-id',operator:'in',values:Array(17).fill('1')},
  ]){
    const wrong=copy(p);
    (wrong.normalization.topFields[prefix+'source-port'] as any).when=bad;
    assert.equal(validateProject(wrong).ok,false,JSON.stringify(bad));
  }
});

test('Juniper vendor-only classifier compiles an explicit, unmodified normalized-path rule',()=>{
  const p=project();
  p.vendor='Juniper';
  p.normalization.vendorFields['syslog_msgid']={normalized_name:'syslog_msgid',data_type:'string'};
  p.classification.rules=[
    {field:'Juniper.syslog_msgid',operator:'equals',value:'RT_FLOW_SESSION_CREATE',index:'session'},
    {field:'Juniper.syslog_msgid',operator:'equals',value:'RT_FLOW_SESSION_CLOSE',index:'session'},
  ];
  assert.deepEqual(validateProject(p),{ok:true,issues:[]});
  const compiled=compilePair(p);
  const ruby=compiled.files.find(file=>!file.name.endsWith('.conf'))?.content;
  assert.ok(ruby);
  const blob=ruby.match(/@parser_rule_set = JSON\.parse\(Base64\.strict_decode64\('([^']+)'\)\)/)?.[1];
  assert.ok(blob);
  const embedded=JSON.parse(Buffer.from(blob,'base64').toString('utf8')) as ParserProject;
  assert.deepEqual(embedded.classification,p.classification);
});

test('Juniper vendor-only RFC5424 message ID classifies session events in generated native Ruby',
  {skip:!rubyAvailable},()=>{
    const p=project();
    p.vendor='Juniper';
    p.normalization.vendorFields['syslog_msgid']={normalized_name:'syslog_msgid',data_type:'string'};
    p.classification.rules=[
      {field:'Juniper.syslog_msgid',operator:'equals',value:'RT_FLOW_SESSION_CREATE',index:'session'},
      {field:'Juniper.syslog_msgid',operator:'equals',value:'RT_FLOW_SESSION_CLOSE',index:'session'},
    ];
    assert.deepEqual(validateProject(p),{ok:true,issues:[]});
    const seed=original[1]!;
    assert.match(seed,/RT_FLOW_SESSION_[A-Z_]+/);
    const make=(messageId:string)=>seed.replace(/RT_FLOW_SESSION_[A-Z_]+/,messageId);
    const rows=runNative(p,[
      make('RT_FLOW_SESSION_CREATE'),
      make('RT_FLOW_SESSION_CLOSE'),
      make('RT_FLOW_OTHER'),
    ]);
    assert.equal(rows.length,3);
    assert.deepEqual(rows.map(row=>row.stellar_log_index),['session','session','syslog']);
    assert.deepEqual(rows.map(row=>row.Juniper?.syslog_msgid),[
      'RT_FLOW_SESSION_CREATE','RT_FLOW_SESSION_CLOSE','RT_FLOW_OTHER',
    ]);
    assert.ok(rows.every(row=>row.parser_err_msg===undefined),JSON.stringify(rows));
  });

for(const withFamily of [false,true]){
  test('Issue #232: '+(withFamily?'family-aware':'standard')+
    ' native Ruby preserves ICMP vendor values and emits only UDP L4 ports',
    {skip:!rubyAvailable},()=>{
      const p=project(withFamily);
      assert.deepEqual(validateProject(p),{ok:true,issues:[]});
      const rows=runNative(p,original);
      assert.equal(rows.length,2);
      assert.equal(rows[0]?.proto,1);
      assert.equal(rows[0]?.srcport,undefined);
      assert.equal(rows[0]?.dstport,undefined);
      assert.equal(rows[1]?.proto,17);
      assert.equal(rows[1]?.srcport,37233);
      assert.equal(rows[1]?.dstport,161);
      const vendor=p.vendor;
      assert.equal(rows[0]?.[vendor]?.original_source_port,'594');
      assert.equal(rows[0]?.[vendor]?.original_destination_port,'10400');
      assert.equal(rows[1]?.[vendor]?.original_source_port,'37233');
      assert.equal(rows[1]?.[vendor]?.original_destination_port,'161');
      assert.ok(rows.every(r=>r.parser_err_stage===undefined),JSON.stringify(rows));
      // Independent TCP/unknown-protocol holdout retains parsed events.
      if(!withFamily){
        const tcp=original[1]!.replace('protocol-id="17"','protocol-id="6"');
        const other=original[1]!.replace('protocol-id="17"','protocol-id="253"');
        const hold=runNative(p,[tcp,other]);
        assert.equal(hold[0]?.srcport,37233);
        assert.equal(hold[0]?.dstport,161);
        assert.equal(hold[1]?.proto,253);
        assert.equal(hold[1]?.srcport,undefined);
        assert.equal(hold[1]?.dstport,undefined);
        assert.equal(hold[1]?.[vendor]?.original_source_port,'37233');
        assert.ok(hold.every(r=>r.parser_err_stage===undefined),JSON.stringify(hold));
      }
    });
}


test('shared named-port alias emits typed ICMP and UDP fields through generated native Ruby',
  {skip:!rubyAvailable},()=>{
    const p=project();
    p.projectId='draft_explicit_named_port_contract';
    p.slug='explicit_named_ports';
    p.normalization.topFields={
      [prefix+'protocol-id']:{normalized_name:'proto',data_type:'integer'},
      [prefix+'source-port']:{normalized_name:'srcport',data_type:'integer'},
      [prefix+'destination-port']:{normalized_name:'dstport',data_type:'integer'},
    };
    p.normalization.vendorFields={};
    assert.deepEqual(validateProject(p),{ok:true,issues:[]});
    const rows=runNative(p,original);
    assert.equal(rows.length,2);
    assert.deepEqual(rows.map(row=>({proto:row.proto,srcport:row.srcport,dstport:row.dstport})),[
      {proto:1,srcport:594,dstport:10400},
      {proto:17,srcport:37233,dstport:161},
    ]);
    assert.ok(rows.every(row=>row.parser_err_stage===undefined),JSON.stringify(rows));
  });

test('Issue #232: integral JSON protocol numbers use browser/Ruby-equivalent exact predicates',
  {skip:!rubyAvailable},()=>{
    const p=sampleProject();
    p.projectId='draft_issue232_numeric_protocol';
    p.slug='issue232_numeric';
    p.extraction={format:'json'};
    p.normalization.topFields={
      proto:{normalized_name:'proto',data_type:'integer'},
      source_port:{normalized_name:'srcport',data_type:'integer',
        when:{sourcePath:'proto',operator:'in',values:['6','17']}},
    };
    p.normalization.nsFields={};
    p.normalization.vendorFields={
      source_port:{normalized_name:'original_source_port',data_type:'string'},
    };
    p.classification.rules=[];
    assert.equal(validateProject(p).ok,true);
    const records=runNative(p,[
      '{"proto":6.0,"source_port":5512}',
      '{"proto":17.0,"source_port":161}',
      '{"proto":1.0,"source_port":8}',
      '{"proto":253.0,"source_port":9000}',
    ]);
    assert.deepEqual(records.map(row=>row.srcport),[5512,161,undefined,undefined]);
    assert.deepEqual(records.map(row=>row.proto),[6,17,1,253]);
    assert.deepEqual(records.map(row=>row[p.vendor]?.original_source_port),
      ['5512','161','8','9000']);
    assert.ok(records.every(row=>row.parser_err_stage===undefined));
  });


test('Issue #232: ambiguous condition source does not promote an official field',
  {skip:!rubyAvailable},()=>{
    const p=sampleProject();
    p.projectId='draft_issue232_ambiguous_condition';
    p.slug='issue232_ambiguous';
    p.extraction={format:'json'};
    p.normalization.topFields={
      port:{normalized_name:'srcport',data_type:'integer',
        when:{sourcePath:'proto.id',operator:'in',values:['6','17']}},
    };
    p.normalization.nsFields={};
    p.normalization.vendorFields={
      user:{normalized_name:'user',data_type:'string'},
      port:{normalized_name:'original_port',data_type:'string'},
    };
    p.classification.rules=[];
    assert.deepEqual(validateProject(p),{ok:true,issues:[]});
    const out=runNative(p,[
      '{"proto":{"id":"6"},"proto.id":"1","user":"alice","port":5001}',
      '{"proto":{"id":"6"},"user":"bob","port":5002}',
    ]);
    assert.equal(out[0]?.srcport,undefined);
    assert.equal(out[0]?.[p.vendor]?.user,'alice');
    assert.equal(out[0]?.[p.vendor]?.original_port,'5001');
    assert.equal(out[1]?.srcport,5002);
    assert.equal(out[1]?.[p.vendor]?.user,'bob');
    assert.ok(out.every(row=>row.parser_err_stage===undefined));
  });
