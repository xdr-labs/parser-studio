/** Independent goldens for compound grammar, relay and framing branches.
 * The eight standard grammar oracles additionally run in backend native tests. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createDraft,type ParserDraft,type MappingRule} from '../../src/model';
import {preview} from '../../src/parser';
import {toBackendProject} from '../../src/guided/backendAdapter';
import {compilePair} from '../../backend/src/compiler';

type Golden={id:string;draft:ParserDraft;raw:string;expected:Record<string,unknown>;bad:string};
const cases:Golden[]=[];
function base(format:ParserDraft['format'],mappings:Array<Omit<MappingRule,'id'>>):ParserDraft{
 const d=createDraft();d.name='Grammar contract';d.vendor='Synthetic';d.format=format;
 d.mappings=mappings.map((m,index)=>({id:'g'+index,...m}));
 d.guided!.classification={defaultIndex:'Syslog',rules:[]};
 d.guided!.groups=Object.fromEntries(d.mappings.map(m=>[m.id,'top_fields']));
 return d;
}
const common=[{source:'srcip',target:'srcip',type:'ip' as const},
 {source:'action',target:'action',type:'string' as const},
 {source:'note',target:'username',type:'string' as const}];
const java=base('java_stacktrace',[
 {source:'exception_class',target:'custom.exception',type:'string'},
 {source:'frame_count',target:'custom.frames',type:'integer'},
]);
java.guided!.eventBoundary='blank-line';java.guided!.receiver.protocols=['tcp'];
java.guided!.receiver.framing='blank_line_java';
cases.push({id:'java-framed',draft:java,
 raw:'java.lang.IllegalStateException: 문제\n\tat com.example.App.main(App.java:42)',
 expected:{custom:{exception:'java.lang.IllegalStateException',frames:1}},
 bad:'java.lang.IllegalStateException: 문제\n\torphaned line'});

const generic=JSON.parse(readFileSync(new URL('../../backend/test/fixtures/mixed-generic-profile-v1.json',import.meta.url),'utf8'));
for(const [index,item] of generic.positive.entries()){
 const prefix=index===0?'generic.kv.':'leef_extension.';
 const d=base('generic_structural',[
  {source:prefix+'src',target:'srcip',type:'ip'},
  {source:prefix+'action',target:'action',type:'string'},
  {source:prefix+(index===0?'user':'usrName'),target:'username',type:'string'},
 ]);
 d.genericStructuralProfile='syslog_prefix_kv_leef2_implicit_tab_v1';
 const values=index===0?item.source.generic.kv:item.source.leef_extension;
 cases.push({id:'generic-profile-'+index,draft:d,raw:item.raw,
  expected:{parserstudio_source:item.source,srcip:values.src,action:values.action,
   username:values[index===0?'user':'usrName']},bad:item.raw+'\v'});
}
const mixed=base('mixed',common);mixed.mixedFormats=['json','kv','cef','leef'];
for(const [format,raw] of [
 ['json','{"srcip":"192.0.2.10","action":"deny","note":"한글🙂"}'],
 ['kv','srcip=192.0.2.10 action=deny note=한글🙂'],
 ['cef','CEF:0|Test|FW|1|100|Blocked|8|srcip=192.0.2.10 action=deny note=한글🙂'],
 ['leef','LEEF:2.0|Test|FW|1|100|^|srcip=192.0.2.10^action=deny^note=한글🙂'],
])cases.push({id:'mixed-'+format,draft:structuredClone(mixed),raw:raw!,
 expected:{srcip:'192.0.2.10',action:'deny',username:'한글🙂'},bad:'unsupported event'});
const csv=base('mixed',common);csv.mixedFormats=['csv','json'];
csv.csvColumns='srcip,action,note';csv.csvDelimiter=',';
cases.push({id:'mixed-csv',draft:csv,raw:'192.0.2.10,deny,한글🙂',
 expected:{srcip:'192.0.2.10',action:'deny',username:'한글🙂'},bad:'bad,"quote'});

for(const format of ['syslog_rfc3164','syslog_rfc5424'] as const){
 const d=base(format,common.map(m=>({...m,source:'body.'+m.source})));
 d.syslogBodyFormat='regex';
 d.pattern='^clock=(?<clock>.+) src=(?<srcip>\\S+) action=(?<action>\\w+) note=(?<note>.+)$';
 const prefix=format==='syslog_rfc3164'?'<134>Nov  8 01:02:03 edge app: ':
  '<134>1 2026-11-08T01:02:03Z edge app - ID - ';
 cases.push({id:format+'-regex-body',draft:d,
  raw:prefix+'clock=12:34:56 src=192.0.2.10 action=deny note=한글🙂',
  expected:{srcip:'192.0.2.10',action:'deny',username:'한글🙂'},
  bad:prefix+'clock=99:99:99 src=192.0.2.10 action=deny note=한글🙂'});
}

const payload='{"srcip":"192.0.2.10","action":"deny","note":"한글🙂"}';
const relayOne='<134>Nov  8 01:02:03 relay01 app: ';
const relayTwo='<134>Nov  8 01:02:04 relay02 app: ';
for(const two of [false,true]){
 const d=base('json',common);d.forwarder={maxHops:2,relayHosts:['relay01','relay02']};
 const prefixes=two?[relayTwo,relayOne]:[relayOne];
 let offset=0;
 const hops=prefixes.map(prefix=>{
  const start=offset;offset+=Buffer.byteLength(prefix,'utf8');
  return {relay_host:prefix===relayOne?'relay01':'relay02',
   relay_timestamp:prefix===relayOne?'Nov  8 01:02:03':'Nov  8 01:02:04',
   envelope:'rfc3164',prefix_start_byte:start,payload_start_byte:offset};
 });
 cases.push({id:two?'forwarder-two-hops':'forwarder-one-hop',draft:d,raw:prefixes.join('')+payload,
  expected:{srcip:'192.0.2.10',action:'deny',username:'한글🙂',
   parserstudio_transport:{forwarder_hops:hops}},
  bad:two?'<134>Nov  8 01:02:03 foreign app: '+payload:relayOne+'unsupported event'});
}

const javaDiscriminator='exception_class';
function family(source:Golden):Golden{
 const result=structuredClone(source),d=result.draft;
 const discriminator=d.format==='java_stacktrace'?javaDiscriminator:
  d.format==='generic_structural'?(source.id.endsWith('0')?'generic.kv.action':'leef_extension.action'):
  d.format==='syslog_rfc3164'||d.format==='syslog_rfc5424'?'body.action':'action';
 const equals=d.format==='java_stacktrace'?'java.lang.IllegalStateException':String(source.expected.action);
 d.eventProfiles={discriminator,unknown:'reject',variants:[
  {name:'security',equals,mappings:[]},{name:'other',equals:'other',mappings:[]},
 ]};
 result.expected.parserstudio_event_family='security';result.id+='-family';return result;
}
const all=cases.flatMap(item=>[item,family(item)]);
const runner=["require 'json'","require 'base64'","input=JSON.parse(STDIN.read)",
 "klass=Class.new","klass.class_eval(Base64.strict_decode64(input.fetch('ruby')).force_encoding('UTF-8'))",
 "parser=klass.new","rows=[]","input.fetch('lines').each{|line|parser.parse(line){|_time,row|rows << row}}",
 "STDOUT.write(JSON.generate(rows))"].join('\n');
assert.equal(spawnSync('ruby',['-v'],{timeout:3000}).status,0,'Native runtime required');
let count=0;const hashes:string[]=[];
for(const item of all){
 const adapted=toBackendProject(item.draft);assert.equal(adapted.ok,true,item.id);
 if(!adapted.ok)throw new Error(item.id);
 const pair=compilePair(adapted.project),ruby=pair.files.find(f=>!f.name.endsWith('.conf'))!;
 hashes.push(ruby.sha256);
 const browser=preview(item.raw,item.draft).events[0]!;
 assert.equal(browser.raw,item.raw,item.id+' immutable original source');
 assert.deepEqual(browser.normalized,item.expected,item.id+' independent browser truth');
 const result=spawnSync('ruby',['-e',runner],{encoding:'utf8',timeout:15000,maxBuffer:2*1024*1024,
  input:JSON.stringify({ruby:Buffer.from(ruby.content).toString('base64'),lines:[item.raw,item.bad,item.raw]})});
 assert.equal(result.status,0,item.id+' native execution failed');
 const rows=JSON.parse(result.stdout) as Record<string,unknown>[];
 assert.equal(rows.length,3,item.id);
 assert.equal(rows[1]!.parser_err_stage,'extraction',item.id+' malformed source');
 assert.equal(rows[1]!.srcip,undefined,item.id+' stale field');
 for(const row of [rows[0]!,rows[2]!]){
  assert.equal(row.parser_err_stage,undefined,item.id);
  const actual=Object.fromEntries(Object.entries(row).filter(([key])=>!['stellar_log_index','msg_origin'].includes(key)));
  assert.deepEqual(actual,item.expected,item.id+' independent native truth');
  count++;
 }
}
console.log(JSON.stringify({contract:'parser-studio.compound-grammar-matrix.v1',projects:all.length,
 records:count,grammars:['java_stacktrace','generic_structural','mixed','syslog_rfc3164_regex_body','syslog_rfc5424_regex_body','declared_forwarder'],templates:['ordinary','family'],
 pairHashSetSha256:createHash('sha256').update(hashes.join('\n')).digest('hex'),
 nativeExecuted:true,targetVerified:false,rawValuesReturned:false}));
