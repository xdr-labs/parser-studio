import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {rubyE} from './ruby-argv.js';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {READING_FAMILY_DISCRIMINATOR} from '../src/canonical-operator-contract.js';
import {sampleProject} from './fixture.js';
import type {ParserProject} from '../src/types.js';

// A mixed parser routed by the family its router read each event with (eventProfiles discriminator
// @reading_family): the Auto Parser draft of golden mixed_envelope_cef_kv. SYNTHETIC lines.
const CEF='<165>1 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dst=198.51.100.4 spt=40000 dpt=443 act=deny';
const KV='<134>Oct 12 01:02:05 fw01 date=2026-10-12 time=01:02:05 srcip=10.5.5.6 srcport=2001 dstip=203.0.113.21 dstport=80 action=deny policyid=9';
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const map=(entries:Record<string,[string,string]>)=>Object.fromEntries(Object.entries(entries)
  .map(([source,[name,type]])=>[source,{normalized_name:name,data_type:type}]));
function project():ParserProject{
  const p=sampleProject();
  p.extraction={format:'mixed',mixedFormats:['json','kv','rfc3164_kv','rfc5424_cef']};
  p.normalization.topFields={};p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[];
  p.normalization.eventProfiles={discriminator:READING_FAMILY_DISCRIMINATOR,unknown:'reject',variants:[
    {name:'rfc5424_cef',equals:'rfc5424_cef',nsFields:{},vendorFields:{},
      topFields:map({'body.src':['srcip','ip'],'body.dst':['dstip','ip'],'body.spt':['srcport','port'],'body.dpt':['dstport','port']})},
    {name:'rfc3164_kv',equals:'rfc3164_kv',nsFields:{},vendorFields:{},
      topFields:map({'body.srcip':['srcip','ip'],'body.dstip':['dstip','ip'],'body.srcport':['srcport','port'],'body.dstport':['dstport','port']})},
    {name:'json',equals:'json',nsFields:{},vendorFields:{},topFields:map({srcip:['srcip','ip']})},
  ]} as ParserProject['normalization']['eventProfiles'];
  return p;
}
function run(p:ParserProject,lines:string[]):Record<string,unknown>[]{
  const code=compilePair(p).files.find(f=>!f.name.endsWith('.conf'))!.content;
  const program=["require 'json'","require 'base64'","require 'time'","require 'ipaddr'",'klass = Class.new',
    "klass.class_eval(Base64.strict_decode64('"+Buffer.from(code).toString('base64')+"'))",'parser = klass.new',
    'STDIN.read.split("\\n").each { |line| parser.parse(line) { |_time, record| puts JSON.generate(record) } }'].join('\n');
  const result=spawnSync('ruby',rubyE(program),{encoding:'utf8',input:lines.join('\n'),timeout:30000,maxBuffer:4*1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return result.stdout.trim().split('\n').map(line=>JSON.parse(line) as Record<string,unknown>);
}

test('the backend accepts @reading_family for a mixed parser only, and only for families it reads',()=>{
  assert.equal(validateProject(project()).ok,true,JSON.stringify(validateProject(project()).issues));
  const json=project();json.extraction={format:'json'};
  assert.ok(validateProject(json).issues.some(issue=>issue.path==='/normalization/eventProfiles/discriminator'));
  const leef=project();leef.normalization.eventProfiles!.variants[2]!.equals='leef';
  assert.ok(validateProject(leef).issues.some(issue=>issue.path==='/normalization/eventProfiles/variants/2/equals'));
});

test('Ruby routes every event by the family the mixed router read it with',{skip:!rubyAvailable},()=>{
  // The JSON line names a family in a field: the reading, not the field, selects the json profile.
  const spoof='{"srcip":"10.9.9.9","@reading_family":"rfc5424_cef"}';
  const out=run(project(),[CEF,KV,spoof,'srcip=10.1.1.1 action=allow']);
  assert.equal(out.length,4);
  const tuple=(record:Record<string,unknown>)=>[record.srcip,record.dstip,record.srcport,record.dstport];
  assert.deepEqual(tuple(out[0]!),['192.0.2.11','198.51.100.4',40000,443]);
  assert.equal(out[0]!.parserstudio_event_family,'rfc5424_cef');
  assert.deepEqual(tuple(out[1]!),['10.5.5.6','203.0.113.21',2001,80]);
  assert.equal(out[1]!.parserstudio_event_family,'rfc3164_kv');
  assert.equal(out[2]!.srcip,'10.9.9.9');
  assert.equal(out[2]!.parserstudio_event_family,'json');
  // A family the parser reads but has no profile for is rejected with its original text, never parsed with
  // the mappings of another family.
  assert.equal(out[3]!.parser_raw_msg,'srcip=10.1.1.1 action=allow');
  assert.equal(out[3]!.srcip,undefined);
  assert.equal(typeof out[3]!.parser_err_msg,'string');
});
