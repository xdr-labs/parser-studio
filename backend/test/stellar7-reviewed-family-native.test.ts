import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';

function project(){
  const p=sampleProject();
  p.projectId='draft_stellar7_conditional';
  p.slug='stellar7_conditional';
  p.vendor='synthetic';
  p.product='Reviewed conditional type mapping';
  p.extraction={format:'json'};
  p.normalization.topFields={event_type:{normalized_name:'event_type',data_type:'string'}};
  p.normalization.nsFields={};
  p.normalization.vendorFields={};
  p.normalization.eventProfiles={
    discriminator:'event_type',unknown:'reject',
    variants:[
      {name:'threat',equals:'threat',
        topFields:{src_ip:{normalized_name:'srcip',data_type:'ip'},
          action:{normalized_name:'action',data_type:'string'}},
        nsFields:{},vendorFields:{}},
      {name:'user',equals:'user',
        topFields:{username:{normalized_name:'username',data_type:'string'}},
        nsFields:{'host.ip':{normalized_name:'host.ip',data_type:'ip'}},vendorFields:{}},
      {name:'asset',equals:'asset',topFields:{},
        nsFields:{'host.name':{normalized_name:'host.name',data_type:'string'},
          'process.name':{normalized_name:'process.name',data_type:'string'}},
        vendorFields:{}},
    ],
  };
  p.classification.rules=[];
  return p;
}

const originals=[
  {event_type:'threat',src_ip:'192.0.2.10',action:'deny'},
  {event_type:'threat',src_ip:'192.0.2.11',action:'block'},
  {event_type:'user',username:'김민수',host:{ip:'198.51.100.5'}},
  {event_type:'user',username:'山田',host:{ip:'198.51.100.6'}},
  {event_type:'asset',host:{name:'asset-01'},process:{name:'sensor.exe'}},
  {event_type:'asset',host:{name:'asset-02'},process:{name:'sensor2.exe'}},
];
const expected=[
  {parserstudio_event_family:'threat',srcip:'192.0.2.10',action:'deny'},
  {parserstudio_event_family:'threat',srcip:'192.0.2.11',action:'block'},
  {parserstudio_event_family:'user',username:'김민수',host:{ip:'198.51.100.5'}},
  {parserstudio_event_family:'user',username:'山田',host:{ip:'198.51.100.6'}},
  {parserstudio_event_family:'asset',host:{name:'asset-01'},process:{name:'sensor.exe'}},
  {parserstudio_event_family:'asset',host:{name:'asset-02'},process:{name:'sensor2.exe'}},
];

test('a reviewed fixed-7.0 conditional DRAFT retains explicit per-family top/ns mapping groups',()=>{
  const p=project();
  assert.deepEqual(validateProject(p),{ok:true,issues:[]});
  const pair=compilePair(p);
  assert.equal(pair.manifest.status,'DRAFT');
  assert.equal(pair.manifest.targetImportVerified,false);
  const ruby=pair.files.find(f=>f.name==='customized_stellar7_conditional')?.content;
  assert.ok(ruby);
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  assert.ok(encoded);
  const parsed=JSON.parse(Buffer.from(encoded,'base64').toString('utf8'));
  assert.equal(parsed.normalization.eventProfiles.unknown,'reject');
  assert.deepEqual(parsed.normalization.eventProfiles.variants[0].topFields.src_ip,
    {normalized_name:'srcip',data_type:'ip'});
  assert.deepEqual(parsed.normalization.eventProfiles.variants[1].nsFields['host.ip'],
    {normalized_name:'host.ip',data_type:'ip'});
  assert.deepEqual(parsed.normalization.eventProfiles.variants[2].nsFields['process.name'],
    {normalized_name:'process.name',data_type:'string'});
  assert.ok(!ruby.includes('김민수'));
  assert.ok(!ruby.includes('192.0.2.10'));
});

const available=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
test('Ruby native parser matches six independent synthetic golden records across three event types',
  {skip:!available},()=>{
  const p=project();
  const ruby=compilePair(p).files.find(f=>f.name==='customized_stellar7_conditional')!.content;
  const program=[
    "require 'json'","require 'base64'","require 'csv'","require 'time'","require 'ipaddr'",
    'klass=Class.new',
    "klass.class_eval(Base64.strict_decode64('"+
      Buffer.from(ruby,'utf8').toString('base64')+"'))",
    'parser=klass.new',
    'results=[]',
    'JSON.parse(STDIN.read).each do |raw|',
    '  parser.parse(raw) { |_time,record| results << record }',
    'end',
    'STDOUT.write(JSON.generate(results))',
  ].join('\n');
  const input=[...originals,{event_type:'unreviewed',src_ip:'203.0.113.10',token:'SECRET_DO_NOT_ECHO'}]
    .map(item=>JSON.stringify(item));
  const result=spawnSync('ruby',['-e',program],{encoding:'utf8',
    input:JSON.stringify(input),timeout:15000,maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  const output=JSON.parse(result.stdout) as Array<Record<string,unknown>>;
  assert.equal(output.length,input.length);
  for(const [i,golden] of expected.entries()){
    const value=output[i];
    assert.ok(value,'Missing record '+i);
    for(const [key,expectedValue] of Object.entries(golden))
      assert.deepEqual(value[key],expectedValue,'Mismatch at '+i+':'+key);
  }
  assert.equal(output[6]?.parser_err_stage,'normalization');
  assert.equal(JSON.stringify(output).includes('SECRET_DO_NOT_ECHO'),false);
});
