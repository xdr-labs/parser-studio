import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import type {ParserProject,ExportFile} from '../src/types.js';

type Profile='syslog_prefix_kv'|'leef2_implicit_tab';
type Source=Record<string,unknown>;
type SyslogSample={name:string;raw:string;prefix:string;kv:Record<string,string>};
type LeefSample={name:string;raw:string;header:Record<string,string>;extension:Record<string,string>};
type RejectedSample={name:string;raw:string};
const syslogFixture=JSON.parse(readFileSync(new URL('../../tests/fixtures/roadmap-syslog-prefix-kv-20261020.json',import.meta.url),'utf8')) as {
  positive:SyslogSample[];negative:RejectedSample[];
};
const leefFixture=JSON.parse(readFileSync(new URL('../../tests/fixtures/roadmap-leef2-implicit-tab-20261020.json',import.meta.url),'utf8')) as {
  positive:LeefSample[];negative:RejectedSample[];
};
const leefPrecedence=JSON.parse(readFileSync(new URL('../../tests/fixtures/roadmap-leef2-precedence-20261020.json',import.meta.url),'utf8')) as {
  positive:LeefSample[];negative:RejectedSample[];
};
const ruby=process.env.PARSER_NATIVE_RUBY||'ruby';
const sha256=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');

// Execute the exact compiler-produced fragment through its public parse
// callback. This standalone Ruby harness does not load Fluentd, parse its
// configuration, open listeners or claim target-loader verification.
const program=[
  "require 'json'", "require 'digest'",
  "input=JSON.parse(STDIN.read)",
  "results=input.fetch('cases').map do |item|",
  "  source=item.fetch('source')",
  "  digest=Digest::SHA256.hexdigest(source)",
  "  raise 'Compiled fragment hash mismatch' unless digest==item.fetch('sha256')",
  "  parser_class=Class.new",
  "  parser_class.class_eval(source,item.fetch('name'),1)",
  "  parser=parser_class.new",
  "  events=item.fetch('events').map do |raw|",
  "    callbacks=[]",
  "    parser.parse(raw) do |time,record|",
  "      callbacks << {'time'=>time.nil? ? nil : time.to_f,'record'=>record}",
  "    end",
  "    {'sourceSha256'=>Digest::SHA256.hexdigest(raw),'callbacks'=>callbacks}",
  "  end",
  "  {'name'=>item.fetch('name'),'sha256'=>digest,'events'=>events}",
  "end",
  "STDOUT.write(JSON.generate({'rubyVersion'=>RUBY_VERSION,'results'=>results}))",
].join('\n');

type ReplayCase={artifact:ExportFile;events:string[]};
type ReplayResult={name:string;sha256:string;events:Array<{
  sourceSha256:string;callbacks:Array<{time:number|null;record:Record<string,unknown>|null}>;
}>};
function replay(cases:ReplayCase[]):ReplayResult[]{
  const result=spawnSync(ruby,['-e',program],{
    input:JSON.stringify({cases:cases.map(item=>({name:item.artifact.name,
      source:item.artifact.content,sha256:item.artifact.sha256,events:item.events}))}),
    encoding:'utf8',timeout:10000,maxBuffer:1024*1024,
  });
  assert.equal(result.status,0,result.stderr||String(result.error));
  const parsed=JSON.parse(result.stdout) as {rubyVersion:string;results:ReplayResult[]};
  assert.match(parsed.rubyVersion,/^\d+\.\d+\.\d+/);
  assert.equal(parsed.results.length,cases.length);
  parsed.results.forEach((item,index)=>{
    const input=cases[index]!;
    assert.equal(item.name,input.artifact.name);
    assert.equal(item.sha256,input.artifact.sha256);
    assert.equal(item.events.length,input.events.length);
    item.events.forEach((event,eventIndex)=>{
      assert.equal(event.sourceSha256,sha256(input.events[eventIndex]!));
      assert.equal(event.callbacks.length,1,'Exactly one parse callback per input event');
    });
  });
  return parsed.results;
}

function artifact(project:ParserProject):ExportFile{
  const pair=compilePair(project);
  assert.equal(pair.manifest.status,'DRAFT');
  assert.equal(pair.manifest.engineVerified,false);
  assert.equal(pair.manifest.targetImportVerified,false);
  for(const file of pair.files){
    assert.equal(file.sha256,sha256(file.content));
    assert.equal(pair.manifest.fileHashes[file.name],file.sha256);
    assert.equal(file.bytes,Buffer.byteLength(file.content,'utf8'));
  }
  const generated=pair.files.find(file=>file.name==='customized_'+project.slug);
  assert.ok(generated,'The compiled extensionless Ruby artifact must exist');
  return generated;
}

function leafStrings(value:Source,prefix=''):Array<[string,string]>{
  const result:Array<[string,string]>=[];
  for(const [key,item] of Object.entries(value)){
    const path=prefix?prefix+'.'+key:key;
    if(typeof item==='string')result.push([path,item]);
    else if(item&&typeof item==='object'&&!Array.isArray(item))
      result.push(...leafStrings(item as Source,path));
  }
  return result;
}

function prepared(profile:Profile,source:Source,kvPath:string,kv:Record<string,string>){
  const project=sampleProject();
  project.slug='profile_callback';project.projectId='draft-profile_callback';
  project.vendor='callback_fixture';project.product='Scoped Ruby callback fixture';
  project.receiver={protocols:['udp'],port:7123,bindAddress:'127.0.0.1',
    messageLengthLimit:65536,tcpFraming:'line'};
  project.extraction={format:'generic_structural',genericStructuralProfile:profile};
  project.normalization.topFields={};project.normalization.nsFields={};
  project.normalization.vendorFields={};delete project.normalization.eventProfiles;
  project.enrichment=[];project.classification={defaultIndex:'syslog',rules:[]};
  const expectedVendor=structuredClone(source);
  const generic=expectedVendor.generic as Source;
  delete generic.mode;delete generic.source_raw;
  if(Object.keys(generic).length===0)delete expectedVendor.generic;
  for(const [path] of leafStrings(expectedVendor)){
    project.normalization.vendorFields[path]={normalized_name:path,data_type:'string'};
  }
  const expectedRecord:Record<string,unknown>={parserstudio_source:source,
    [project.vendor]:expectedVendor,stellar_log_index:'syslog',msg_origin:{
      source:project.normalization.msgOriginSource,
      category:project.normalization.msgOriginCategory,
      class:project.normalization.msgClass,
    }};
  for(const [key,target,type] of [
    ['src','srcip','ip'],['dst','dstip','ip'],['action','action','string'],
  ] as const){
    if(kv[key]===undefined)continue;
    project.normalization.topFields[kvPath+'.'+key]={normalized_name:target,data_type:type};
    expectedRecord[target]=kv[key];
  }
  return {project,expectedRecord};
}

function syslogCase(sample:SyslogSample){
  // These golden headers correspond to the authored shared fixture records;
  // the expected values do not invoke the extraction helper under test.
  const header=sample.name==='multilingual vendor-neutral holdout'
    ?{pri:'165',month:'Feb',day:'9',time:'03:04:05',hostname:'host02'}
    :{pri:'134',month:'Oct',day:'19',time:'08:23:59',hostname:'ftd01'};
  const message=sample.raw.slice(sample.raw.indexOf(sample.prefix));
  const source={syslog:{...header,time_policy:'YEAR_AND_ZONE_UNKNOWN'},
    generic:{mode:'syslog_prefix_kv',prefix:sample.prefix,message_raw:message,
      source_raw:sample.raw,kv:sample.kv}};
  return {sample,...prepared('syslog_prefix_kv',source,'generic.kv',sample.kv)};
}
function leefCase(sample:LeefSample){
  const source={leef_header:sample.header,leef_extension:sample.extension,
    generic:{mode:'leef2_implicit_tab',source_raw:sample.raw}};
  return {sample,...prepared('leef2_implicit_tab',source,'leef_extension',sample.extension)};
}

for(const [profile,cases] of [
  ['syslog_prefix_kv',syslogFixture.positive.map(syslogCase)],
  ['leef2_implicit_tab',[...leefFixture.positive,...leefPrecedence.positive].map(leefCase)],
] as const){
  test('compiled '+profile+' artifact preserves source and all mapped fields through the Ruby parse callback',()=>{
    const outputs=replay(cases.map(item=>({artifact:artifact(item.project),events:[item.sample.raw]})));
    outputs.forEach((output,index)=>{
      const callback=output.events[0]!.callbacks[0]!;
      // The log carries no usable year or timestamp, so the event time is the receive time
      // (never derived from the log, and never nil: Stellar's receivers report a nil time
      // as "pattern not matched").
      assert.equal(typeof callback.time,'number','a parsed event must carry the receive time');
      assert.ok(Math.abs((callback.time as number)-Date.now()/1000)<60,'event time is the receive time');
      assert.deepEqual(callback.record,cases[index]!.expectedRecord,cases[index]!.sample.name);
    });
  });
}

test('compiled callbacks reject new-profile events when the selected grammar is absent or different',()=>{
  const inputs=[syslogCase(syslogFixture.positive[0]!),leefCase(leefFixture.positive[0]!)];
  const cases:ReplayCase[]=[];
  for(const input of inputs){
    const absent=structuredClone(input.project);delete absent.extraction.genericStructuralProfile;
    const different=structuredClone(input.project);
    different.extraction.genericStructuralProfile=input.project.extraction.genericStructuralProfile==='syslog_prefix_kv'
      ?'leef2_implicit_tab':'syslog_prefix_kv';
    for(const project of [absent,different])cases.push({artifact:artifact(project),events:[input.sample.raw]});
  }
  for(const output of replay(cases))assert.deepEqual(output.events[0]!.callbacks[0],{
    time:null,record:{stellar_log_index:'syslog',parser_err_msg:'ArgumentError',parser_err_stage:'extraction'},
  });
});

test('compiled callbacks retain static extraction errors for malformed profile records',()=>{
  const syslogNames=['invalid priority','duplicate key','unclosed quote','trailing prose'];
  const leefNames=['duplicate extension key','single extension field','trailing TAB','unsafe constructor key'];
  const samples=[
    {project:syslogCase(syslogFixture.positive[0]!).project,
      events:syslogFixture.negative.filter(item=>syslogNames.includes(item.name)).map(item=>item.raw)},
    {project:leefCase(leefFixture.positive[0]!).project,
      events:leefFixture.negative.filter(item=>leefNames.includes(item.name)).map(item=>item.raw)},
  ];
  for(const sample of samples)assert.equal(sample.events.length,4,'Every named negative control must be present');
  for(const output of replay(samples.map(item=>({artifact:artifact(item.project),events:item.events})))){
    for(const event of output.events)assert.deepEqual(event.callbacks[0],{
      time:null,record:{stellar_log_index:'syslog',parser_err_msg:'ArgumentError',parser_err_stage:'extraction'},
    });
  }
});


test('compiled selected LEEF callback refuses out-of-profile standalone input before legacy KV fallback',()=>{
  const project=leefCase(leefPrecedence.positive[0]!).project;
  const [output]=replay([{artifact:artifact(project),events:leefPrecedence.negative.map(item=>item.raw)}]);
  for(const event of output!.events)assert.deepEqual(event.callbacks[0],{
    time:null,record:{stellar_log_index:'syslog',parser_err_msg:'ArgumentError',parser_err_stage:'extraction'},
  });
});
