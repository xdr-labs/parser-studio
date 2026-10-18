import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import type {ParserProject} from '../src/types.js';

const rubyPresent=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
function project():ParserProject{
  const p=sampleProject();
  p.projectId='draft_synthetic_family_native';
  p.slug='family_native';
  p.extraction={format:'json',forwarder:{maxHops:2,relayHosts:['relay01','relay02']}};
  p.normalization.topFields={
    event_type:{normalized_name:'event_type',data_type:'string'},
  };
  p.normalization.nsFields={};
  p.normalization.vendorFields={};
  p.normalization.eventProfiles={
    discriminator:'event_type',unknown:'reject',variants:[
      {name:'threat',equals:'threat',topFields:{
        src_ip:{normalized_name:'srcip',data_type:'ip'},
      },nsFields:{},vendorFields:{}},
      {name:'user',equals:'user',topFields:{
        username:{normalized_name:'username',data_type:'string'},
      },nsFields:{},vendorFields:{}},
      {name:'asset',equals:'asset',topFields:{
        hostname:{normalized_name:'host_name',data_type:'string'},
      },nsFields:{},vendorFields:{}},
    ],
  };
  p.classification.rules=[];
  return p;
}
function nativeRun(p:ParserProject,raw:string):Record<string,unknown>{
  const files=compilePair(p).files;
  const ruby=files.find(x=>!x.name.endsWith('.conf'))!.content;
  const script=ruby+'\ninitialize()\nparse('+JSON.stringify(raw)+
    ') { |time, result| STDOUT.write(JSON.generate(result)) }\n';
  const out=spawnSync('ruby',['-e',script],{
    encoding:'utf8',timeout:5000,maxBuffer:512*1024,
  });
  assert.equal(out.status,0,out.stderr||String(out.error));
  return JSON.parse(out.stdout) as Record<string,unknown>;
}

test('native Ruby executes one bounded compiled parser across threat, user and asset samples',
  {skip:!rubyPresent},()=>{
  const p=project();
  for(const [family,field,target,value] of [
    ['threat','src_ip','srcip','198.51.100.10'],
    ['user','username','username','example_user'],
    ['asset','hostname','host_name','device01'],
  ] as const){
    const raw=JSON.stringify({event_type:family,[field]:value});
    const result=nativeRun(p,raw);
    assert.equal(result['parserstudio_event_family'],family);
    assert.equal(result['event_type'],family);
    assert.equal(result[target],value);
    assert.equal(result['stellar_log_index'],'syslog');
  }
});
test('native Ruby unwraps only declared forwarders while retaining bounded source provenance',
  {skip:!rubyPresent},()=>{
  const p=project();
  const event=JSON.stringify({event_type:'threat',src_ip:'192.0.2.10'});
  const raw='<134>Oct 19 10:02:03 relay01 fwd: '+
    '<134>Oct 19 10:02:04 relay02 fwd: '+event;
  const result=nativeRun(p,raw);
  assert.equal(result['parserstudio_event_family'],'threat');
  assert.equal(result['srcip'],'192.0.2.10');
  const transport=result['parserstudio_transport'] as {forwarder_hops:Array<{
    relay_host:string;payload_start_byte:number;
  }>};
  assert.deepEqual(transport.forwarder_hops.map(x=>x.relay_host),
    ['relay01','relay02']);
  assert.ok(transport.forwarder_hops[0]!.payload_start_byte>0);
  assert.ok(transport.forwarder_hops[1]!.payload_start_byte>
    transport.forwarder_hops[0]!.payload_start_byte);
});
test('native Ruby rejects unknown source families, undeclared relays and hop limit overflow',
  {skip:!rubyPresent},()=>{
  const p=project();
  const source=JSON.stringify({event_type:'unknown',username:'example'});
  const unknown=nativeRun(p,source);
  assert.equal(unknown['parser_err_msg'],'MappedFieldError');
  assert.equal(unknown['parser_err_stage'],'normalization');
  assert.equal(unknown['parserstudio_event_family'],undefined);
  const body=JSON.stringify({event_type:'threat',src_ip:'192.0.2.1'});
  const relayed='<134>Oct 19 10:02:03 otherrelay fwd: '+body;
  const denied=nativeRun(p,relayed);
  assert.equal(denied['parser_err_stage'],'extraction');
  assert.equal(denied['srcip'],undefined);
  const one={...p,extraction:{...p.extraction,forwarder:{maxHops:1 as const,relayHosts:['relay01','relay02']}}};
  const nested='<134>Oct 19 10:02:03 relay01 fwd: '+
    '<134>Oct 19 10:02:04 relay02 fwd: '+body;
  const overflow=nativeRun(one,nested);
  assert.equal(overflow['parser_err_stage'],'extraction');
  assert.equal(overflow['srcip'],undefined);
});
