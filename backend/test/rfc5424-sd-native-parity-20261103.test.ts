import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';

/**
 * Actual generated Ruby callback golden: RFC5424 SD-PARAM fields must be
 * independently mappable, not only preserved in one raw SD string.
 * Offline only; not a Fluentd plugin or Stellar DP certification.
 */
test('generated RFC5424 Ruby preserves Juniper source/destination/policy fields',()=>{
  const project=sampleProject();
  project.projectId='synthetic-rfc5424-sd-field-parity';
  project.slug='rfc5424_sd_parity';
  project.extraction={format:'syslog_rfc5424',syslogBodyFormat:'raw'};
  project.normalization.topFields={
    'syslog_sd.element_1.params.source-address':{normalized_name:'srcip',data_type:'ip'},
    'syslog_sd.element_1.params.destination-address':{normalized_name:'dstip',data_type:'ip'},
    'syslog_sd.element_1.params.source-port':{normalized_name:'srcport',data_type:'port'},
    'syslog_sd.element_1.params.destination-port':{normalized_name:'dstport',data_type:'port'},
    syslog_timestamp:{normalized_name:'timestamp',data_type:'date',time_format:'iso8601',timezone:'UTC'},
  };
  project.normalization.nsFields={};
  project.normalization.vendorFields={
    'syslog_sd.element_1.params.policy-name':{normalized_name:'policy_name',data_type:'string'},
    'syslog_sd.element_1.params.reason':{normalized_name:'reason',data_type:'string'},
  };
  project.classification.rules=[];
  const validated=validateProject(project);
  assert.equal(validated.ok,true,JSON.stringify(validated.issues));
  const pair=compilePair(project);
  assert.equal(pair.manifest.engineVerified,false);
  assert.equal(pair.manifest.targetImportVerified,false);
  const ruby=pair.files.find(file=>file.name==='customized_rfc5424_sd_parity');
  assert.ok(ruby);
  const raw='<14>1 2019-11-14T11:12:46.573+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_DENY '+
    '[junos@67.43.156.15 source-address="10.0.0.26" source-port="37233" '+
    'destination-address="67.43.156.13" destination-port="161" '+
    'policy-name="MgmtAccess-trust-cleanup" reason="Denied by policy"]';
  const runner=[
    "require 'json'",
    'input=JSON.parse(STDIN.read)',
    'klass=Class.new',
    "klass.class_eval(input.fetch('source'),'generated_rfc5424_sd',1)",
    'parser=klass.new',
    'record=nil',
    "parser.parse(input.fetch('raw')){|_time,event|record=event}",
    'STDOUT.write(JSON.generate(record))',
  ].join('\n');
  const result=spawnSync(process.env.PARSER_RUBY_BIN||'ruby',['-e',runner],{
    input:JSON.stringify({source:ruby.content,raw}),encoding:'utf8',timeout:15000,
    maxBuffer:1024*1024,
  });
  assert.equal(result.status,0,String(result.stderr));
  const record=JSON.parse(result.stdout) as Record<string,any>;
  assert.equal(record.parser_err_msg,undefined);
  assert.equal(record.srcip,'10.0.0.26');
  assert.equal(record.dstip,'67.43.156.13');
  assert.equal(record.srcport,37233);
  assert.equal(record.dstport,161);
  assert.equal(record.Synthetic.policy_name,'MgmtAccess-trust-cleanup');
  assert.equal(record.Synthetic.reason,'Denied by policy');
});
