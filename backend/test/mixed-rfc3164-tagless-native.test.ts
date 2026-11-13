import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

// The browser accepts a tagless BSD syslog header ("<PRI>Mon DD HH:MM:SS host
// key=value") inside a mixed project because the backend advertises
// rfc3164TaglessStructuredSecuritySubset. The generated Ruby must accept the
// same lines, never reconstruct year/zone, and still refuse everything else.
function mixedProject(formats:string[]){
  const p=sampleProject();
  p.projectId='draft-mixed_tagless';p.slug='mixed_tagless';p.receiver.port=6803;
  p.extraction={format:'mixed',mixedFormats:formats} as any;
  p.normalization.topFields={
    'body.srcip':{normalized_name:'srcip',data_type:'ip'},
    'body.action':{normalized_name:'action',data_type:'string'},
    'syslog_time_policy':{normalized_name:'time_policy',data_type:'string'},
  };
  p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[{field:'action',operator:'equals',value:'deny',index:'threat'}];
  return p;
}
function runCompiled(formats:string[],raws:string[]):Array<Record<string,unknown>>{
  const project=mixedProject(formats);
  assert.equal(validateProject(project).ok,true,JSON.stringify(validateProject(project)));
  const ruby=compilePair(project).files[1]!.content;
  const probe=[
    "require 'json'",
    "class QuietLog; def method_missing(*); nil; end; def respond_to_missing?(*); true; end; end",
    "class BaseParser; def initialize(*); end; def configure(*); end; def log; @log ||= QuietLog.new; end; end",
    "input = JSON.parse(STDIN.read)",
    "inner = Class.new(BaseParser) { def set_inner_class_params(*); end; def stellar_inner_class_get_parser_rule_set; @parser_rule_set; end }",
    "inner.class_eval(input['ruby'], 'artifact', 1)",
    "parser = inner.new",
    "out = input['raws'].map { |raw| rec = nil; parser.parse(raw) { |_t, r| rec = r }; rec }",
    "STDOUT.write(JSON.generate(out))",
  ].join('\n');
  const out=spawnSync('ruby',['-e',probe],{input:JSON.stringify({ruby,raws}),encoding:'utf8',timeout:20000,maxBuffer:1<<22});
  assert.equal(out.status,0,out.stderr||String(out.error));
  return JSON.parse(out.stdout);
}

test('mixed RFC3164 KV accepts the tagless structured header the browser accepts',{skip:!rubyAvailable},()=>{
  const [withPri,noPri,tagged]=runCompiled(['rfc3164_kv','rfc5424_cef'],[
    '<134>Oct 12 01:02:05 fw01 date=2026-10-12 srcip=10.5.5.6 action=deny',
    'Oct 12 01:02:05 fw01 date=2026-10-12 srcip=10.5.5.7 action=allow',
    '<134>Oct 12 01:02:05 fw01 sshd: srcip=10.5.5.8 action=deny',
  ]) as any[];
  for(const record of [withPri,noPri,tagged])assert.equal(record.parser_err_msg,undefined,JSON.stringify(record));
  assert.equal(withPri.srcip,'10.5.5.6');
  assert.equal(withPri.action,'deny');
  assert.equal(withPri.time_policy,'YEAR_AND_ZONE_UNKNOWN');
  assert.equal(noPri.srcip,'10.5.5.7');
  assert.equal(tagged.srcip,'10.5.5.8');
});

test('mixed RFC3164 tagless negative controls stay fail-closed',{skip:!rubyAvailable},()=>{
  const records=runCompiled(['rfc3164_kv','rfc5424_cef'],[
    '<134>Oct 12 01:02:05 fw01 this is only prose without a structured body',
    '<134>Oct 12 01:02:05 fw01 {"srcip":"10.5.5.6"}',
    '<134>Feb 30 01:02:05 fw01 srcip=10.5.5.6 action=deny',
    '<192>Oct 12 01:02:05 fw01 srcip=10.5.5.6 action=deny',
    '<134>Oct 12 25:02:05 fw01 srcip=10.5.5.6 action=deny',
  ]) as any[];
  for(const record of records){
    assert.equal(typeof record.parser_err_msg,'string',JSON.stringify(record));
    assert.equal(record.srcip,undefined);
  }
  // A family that was not reviewed into this mixed project is still refused.
  const [disallowed]=runCompiled(['rfc5424_cef','json'],['<134>Oct 12 01:02:05 fw01 srcip=10.5.5.6 action=deny']) as any[];
  assert.equal(typeof disallowed.parser_err_msg,'string');
  assert.equal(disallowed.srcip,undefined);
});
