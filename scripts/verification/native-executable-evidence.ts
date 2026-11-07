/**
 * CI-only, independently authored synthetic source → exact generated Ruby
 * execution evidence. This program accepts NO CLI input/customer events and
 * does NOT make arbitrary generated Ruby execution available to any HTTP API.
 *
 * Output is safe receipt metadata (hashes and counts only), not source text.
 * Fluentd/Sensor/DP target compatibility remains NOT_VERIFIED.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {compilePair} from '../../backend/src/compiler';
import {validateProject} from '../../backend/src/validate';
import {sampleProject} from '../../backend/test/fixture';

const hash=(text:string)=>createHash('sha256').update(text,'utf8').digest('hex');

// Independent official-field policy requires original source `action` to be
// TEXT, even if a generic string mapping can stringify JSON numeric values.
// The numeric second event must fail closed with an explicit normalization
// diagnostic, preserve its unrelated valid IP and never emit official action.
// Oracle expectations are authored from the pinned Stellar 7.0 policy, not
// derived from browser/native implementation output.
const oracle=[
  {raw:'{"status":"0006","client_ip":"192.0.2.10"}',
    expected:{action:'0006',srcip:'192.0.2.10',stellar_log_index:'threat'},
    absent:[] as string[]},
  {raw:'{"status":6,"client_ip":"198.51.100.7"}',
    expected:{srcip:'198.51.100.7',stellar_log_index:'syslog',
      parser_err_msg:'MappedFieldError',parser_err_stage:'normalization',
      parser_err_field:'status'},absent:['action']},
  {raw:'{"status":"6","client_ip":"203.0.113.9"}',
    expected:{action:'6',srcip:'203.0.113.9',stellar_log_index:'syslog'},
    absent:[] as string[]},
];

const runner=[
  "require 'json'","require 'base64'","require 'time'","require 'date'",
  "require 'ipaddr'","require 'csv'",
  "input=JSON.parse(STDIN.read)",
  "parser_class=Class.new",
  "parser_class.class_eval(Base64.strict_decode64(input.fetch('ruby')),'native-evidence',1)",
  "parser=parser_class.new",
  "rows=[]",
  "input.fetch('events').each{|raw|parser.parse(raw){|_time,record|rows << record}}",
  "STDOUT.write(JSON.generate(rows))",
].join('\n');

function main(){
  const runtime=spawnSync('ruby',['-v'],{encoding:'utf8',timeout:3000});
  assert.equal(runtime.status,0,
    'A real Ruby interpreter is required; do not skip synthetic Native execution');

  const project=sampleProject();
  project.extraction={format:'json'};
  project.normalization.topFields={
    status:{normalized_name:'action',data_type:'string'},
    client_ip:{normalized_name:'srcip',data_type:'ip'},
  };
  project.normalization.nsFields={};
  project.normalization.vendorFields={};
  project.classification={defaultIndex:'syslog',rules:[
    {field:'action',operator:'equals',value:'0006',index:'threat'},
  ]};
  assert.equal(validateProject(project).ok,true,'Oracle project must be valid');
  const pair=compilePair(project);
  assert.equal(pair.manifest.status,'DRAFT');
  assert.equal(pair.manifest.engineVerified,false);
  assert.equal(pair.manifest.targetImportVerified,false);
  assert.equal(pair.files.length,2);
  const parser=pair.files.find(file=>!file.name.endsWith('.conf'))!;
  const conf=pair.files.find(file=>file.name.endsWith('.conf'))!;
  assert.equal(conf.name,parser.name+'.conf');
  assert.equal(hash(parser.content),parser.sha256);
  assert.equal(hash(conf.content),conf.sha256);
  assert.match(parser.content,/Canonical classifier contract: parser-studio\.operator-semantics\.v1/);

  const execution=spawnSync('ruby',['-e',runner],{
    encoding:'utf8',timeout:12000,maxBuffer:1024*1024,
    input:JSON.stringify({
      ruby:Buffer.from(parser.content,'utf8').toString('base64'),
      events:oracle.map(entry=>entry.raw),
    }),
  });
  assert.equal(execution.status,0,'Generated Ruby callback must execute successfully');
  const actual=JSON.parse(execution.stdout) as Array<Record<string,unknown>>;
  assert.equal(actual.length,oracle.length,'No missing or fabricated events');
  for(let i=0;i<oracle.length;i++){
    const record=actual[i]!;
    for(const [field,value] of Object.entries(oracle[i]!.expected))
      assert.equal(record[field],value,`Native mismatch in synthetic event ${i+1}, field ${field}`);
    for(const forbidden of oracle[i]!.absent)
      assert.equal(Object.hasOwn(record,forbidden),false,
        `Unexpected official field in failed synthetic event ${i+1}: ${forbidden}`);
  }
  // Receipt contains no raw events, normalized values, Ruby code, passwords or
  // environment values. It is explicitly not a per-user parser validation.
  const receipt={
    contract:'parser-studio.native-executable-evidence.v1',
    scope:'fixed-synthetic-ruby-callback-only',
    verifiedEventCount:oracle.length,
    verifiedFieldCount:oracle.reduce((sum,event)=>sum+Object.keys(event.expected).length+event.absent.length,0),
    sourceSha256:hash(oracle.map(entry=>entry.raw).join('\n')),
    parserSha256:parser.sha256,
    confSha256:conf.sha256,
    rubyRuntimeVersion:runtime.stdout.trim(),
    nativeRubyExecuted:true,
    fluentdIntegrationExecuted:false,
    sourceFixtureIndependentOracle:true,
    userParserVerified:false,
    stellarTargetImportVerified:false,
    externalSensorTrafficSent:false,
    rawValuesReturned:false,
  };
  process.stdout.write(JSON.stringify(receipt)+'\n');
}
main();
