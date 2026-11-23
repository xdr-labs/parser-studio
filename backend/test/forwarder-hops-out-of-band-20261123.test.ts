import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdirSync,writeFileSync} from 'node:fs';
import test from 'node:test';
import {rubyE} from './ruby-argv.js';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';

// Independent audit 2026-11-23 (P1): the generated Ruby kept the relay hops it unwrapped in the parsed record,
// under __parserstudio_forwarder_hops, and read them back from there for parserstudio_transport. A JSON event
// with a member of that name therefore produced transport metadata that no relay wrote (the browser preview did
// not), and a relayed key=value event could have its hops replaced by a pair of that name. The hops now travel
// out of band, like the reading family. SYNTHETIC lines.
const rubyPresent=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
function project(){
  const p=sampleProject();
  p.projectId='draft_forwarder_out_of_band';p.slug='forwarder_out_of_band';
  p.extraction={format:'mixed',mixedFormats:['json','kv'],forwarder:{maxHops:2,relayHosts:['relay01','relay02']}};
  p.normalization.topFields={src_ip:{normalized_name:'srcip',data_type:'ip'}};
  p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[];
  return p;
}
function run(lines:string[]):Record<string,unknown>[]{
  const fragment=compilePair(project()).files.find(file=>!file.name.endsWith('.conf'))!.content;
  // With Q31_RB_DIR set, the parser and its lines are also written there for the Ruby 2.4.9 runner.
  if(process.env.Q31_RB_DIR){
    mkdirSync(process.env.Q31_RB_DIR,{recursive:true});
    writeFileSync(process.env.Q31_RB_DIR+'/forwarder.rb',fragment);
    writeFileSync(process.env.Q31_RB_DIR+'/forwarder.lines',lines.join('\n')+'\n');
  }
  const script=["require 'json'","require 'base64'","require 'csv'","require 'time'","require 'ipaddr'",
    'klass=Class.new',"klass.class_eval(Base64.strict_decode64('"+Buffer.from(fragment,'utf8').toString('base64')+"'))",
    'instance=klass.new','results=[]','JSON.parse(STDIN.read).each do |line|',
    ' instance.parse(line) {|time,record| results << record }','end','STDOUT.write(JSON.generate(results))'].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',input:JSON.stringify(lines),timeout:12000,
    maxBuffer:2*1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout) as Record<string,unknown>[];
}
const hops=(record:Record<string,unknown>|undefined)=>
  (record?.parserstudio_transport as {forwarder_hops?:unknown[]}|undefined)?.forwarder_hops;

test('a source member named like the internal hop list writes no transport metadata',{skip:!rubyPresent},()=>{
  const spoof='{"src_ip":"192.0.2.10","__parserstudio_forwarder_hops":[{"host":"relay01","pri":134}]}';
  const spoofKv='src_ip=192.0.2.11 __parserstudio_forwarder_hops=relay01';
  const threat='{"src_ip":"192.0.2.12"}';
  const relayed='<134>Jan 16 15:19:05 relay01 fw: '+threat;
  const relayedSpoof='<134>Jan 16 15:19:05 relay01 fw: '+spoof;
  const records=run([spoof,spoofKv,relayed,relayedSpoof]);
  assert.equal(records.length,4);
  assert.equal(records[0]?.srcip,'192.0.2.10');
  assert.equal(records[0]?.parserstudio_transport,undefined);
  assert.equal(records[1]?.srcip,'192.0.2.11');
  assert.equal(records[1]?.parserstudio_transport,undefined);
  // A relay the project declares still records its hop, and only the hop it unwrapped.
  assert.equal(records[2]?.srcip,'192.0.2.12');
  assert.equal(hops(records[2])?.length,1);
  assert.equal(records[3]?.srcip,'192.0.2.10');
  assert.equal(hops(records[3])?.length,1);
  assert.equal(JSON.stringify(hops(records[3])),JSON.stringify(hops(records[2])));
});
