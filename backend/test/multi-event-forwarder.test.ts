import test from 'node:test';
import {spawnSync} from 'node:child_process';
import type {AddressInfo} from 'node:net';
import {createMainlineAuthoringServer} from '../src/mainline-authoring-server.js';
import assert from 'node:assert/strict';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {BACKEND_CAPABILITIES} from '../src/capabilities.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';

function project(){
 const p=sampleProject();
 p.projectId='draft_family_forwarder';p.slug='family_forwarder';
 p.extraction={format:'mixed',mixedFormats:['json','kv'],
   forwarder:{maxHops:2,relayHosts:['relay01','relay02']}};
 p.normalization.topFields={event_type:{normalized_name:'event_type',data_type:'string'}};
 p.normalization.nsFields={};
 p.normalization.vendorFields={};
 p.normalization.eventProfiles={
  discriminator:'event_type',unknown:'reject',
  variants:[
   {name:'threat',equals:'threat',topFields:{
      src_ip:{normalized_name:'srcip',data_type:'ip'}},nsFields:{},vendorFields:{}},
   {name:'user',equals:'user',topFields:{
      username:{normalized_name:'username',data_type:'string'}},nsFields:{},vendorFields:{}},
   {name:'asset',equals:'asset',topFields:{
      hostname:{normalized_name:'host_name',data_type:'string'}},nsFields:{},vendorFields:{}},
  ]
 };
 p.classification.rules=[];
 return p;
}

test('single-artefact multi-event parser compiles with strict family and declared relay profiles',()=>{
 const p=project();
 assert.deepEqual(validateProject(p),{ok:true,issues:[]});
 const output=compilePair(p);
 assert.deepEqual(output.files.map(f=>f.name),['customized_family_forwarder.conf','customized_family_forwarder']);
 assert.equal(output.manifest.engineVerified,false);
 assert.equal(output.manifest.targetImportVerified,false);
 const ruby=output.files.find(f=>f.name==='customized_family_forwarder')?.content??'';
 assert.match(ruby,/def parserstudio_unwrap_declared_relays/);
 assert.match(ruby,/parserstudio_event_profile\(original\)/);
 assert.match(ruby,/def parserstudio_apply_field_maps/);
 assert.match(ruby,/parserstudio_transport/);
 assert.match(ruby,/raise ParserstudioFieldError.new\(key\) unless profiles.length == 1/);
 const base64=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
 assert.ok(base64);
 const encoded=JSON.parse(Buffer.from(base64,'base64').toString('utf8'));
 assert.deepEqual(encoded.extraction.forwarder,{maxHops:2,relayHosts:['relay01','relay02']});
 assert.equal(encoded.normalization.eventProfiles.variants.length,3);
 assert.equal(encoded.normalization.eventProfiles.variants[2].name,'asset');
 assert.equal(output.files.filter(f=>f.name.endsWith('.conf')).length,1);
 assert.equal(BACKEND_CAPABILITIES.authoring.conditionalEventProfiles,true);
 assert.equal(BACKEND_CAPABILITIES.authoring.declaredForwarderMaximumHops,3);
 assert.throws(()=>recipeFromLegacyProject(p,'a'.repeat(64),3),/UNSUPPORTED_RECIPE_PROJECTION/,
   'v0.2 review projection must not silently omit event family or relay logic');
});
test('per-family field destinations may differ, but conflicts with common mappings fail',()=>{
 const p=project();
 assert.equal(validateProject(p).ok,true);
 p.normalization.eventProfiles!.variants[0]!.topFields.src_ip!.normalized_name='event_type';
 const result=validateProject(p);
 assert.equal(result.ok,false);
 assert.ok(result.issues.some(x=>x.code==='destination_collision'));
});
test('duplicate and unsafe event-family routing rejected',()=>{
 const cases:Array<(p:ReturnType<typeof project>)=>void>=[
  p=>{p.normalization.eventProfiles!.variants[1]!.equals='threat';},
  p=>{p.normalization.eventProfiles!.variants[1]!.name='threat';},
  p=>{p.normalization.eventProfiles!.variants[0]!.topFields['constructor']={
     normalized_name:'custom',data_type:'string' as const};},
  p=>{p.normalization.eventProfiles!.unknown='fallback' as 'reject';},
  p=>{p.normalization.eventProfiles!.discriminator='constructor';},
  p=>{p.normalization.eventProfiles!.variants=[p.normalization.eventProfiles!.variants[0]!];},
  p=>{p.extraction.forwarder!.maxHops=4 as 3;},
  p=>{p.extraction.forwarder!.relayHosts=[];},
  p=>{p.extraction.forwarder!.relayHosts=['relay01','relay01'];},
  p=>{p.extraction.forwarder!.relayHosts=['.*/'];},
  p=>{p.extraction.format='regex';},
 ];
 for(const mutate of cases){
  const p=project();mutate(p);
  assert.equal(validateProject(p).ok,false,JSON.stringify(p));
  assert.throws(()=>compilePair(p),/Invalid parser project/);
 }
});
test('profile-free old projects remain accepted and unchanged in schema',()=>{
 const p=sampleProject();
 assert.equal(validateProject(p).ok,true);
 assert.equal(p.normalization.eventProfiles,undefined);
 assert.equal(p.extraction.forwarder,undefined);
 const compiled=compilePair(p);
 const fragment=compiled.files.find(f=>!f.name.endsWith('.conf'))?.content??'';
 assert.doesNotMatch(fragment,/def parserstudio_unwrap_declared_relays/);
 assert.equal(compiled.files.length,2);
 assert.equal(compiled.manifest.engineVerified,false);
});

const rubyPresent=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
test('actual generated Ruby branches threat/user/asset and rejects unknown family without source egress',
  {skip:!rubyPresent},()=>{
  const p=project();
  const compiled=compilePair(p);
  const fragment=compiled.files.find(f=>!f.name.endsWith('.conf'))!.content;
  const script=[
    "require 'json'","require 'base64'","require 'csv'","require 'time'","require 'ipaddr'",
    "klass=Class.new",
    'klass.class_eval('+JSON.stringify(fragment)+')',
    'instance=klass.new',
    'results=[]',
    'JSON.parse(STDIN.read).each do |line|',
    ' instance.parse(line) {|time,record| results << record }',
    'end',
    'STDOUT.write(JSON.generate(results))'
  ].join('\n');
  const threat='{"event_type":"threat","src_ip":"192.0.2.10"}';
  const user='{"event_type":"user","username":"김민수"}';
  const asset='{"event_type":"asset","hostname":"fw01"}';
  const relayed='<134>Jan 16 15:19:05 relay01 fw: '+threat;
  const twice='<134>Jan 16 15:19:05 relay02 fw: '+relayed;
  const foreign='<134>Jan 16 15:19:05 unknown-relay fw: '+threat;
  const unknown='{"event_type":"unreviewed","user":"DO_NOT_ECHO_PRIVATE"}';
  const input=[threat,user,asset,relayed,twice,foreign,unknown];
  const result=spawnSync('ruby',['-e',script],{
    encoding:'utf8',input:JSON.stringify(input),timeout:12000,maxBuffer:2*1024*1024,
  });
  assert.equal(result.status,0,result.stderr||String(result.error));
  const records=JSON.parse(result.stdout) as Array<Record<string,unknown>>;
  assert.equal(records.length,input.length);
  assert.equal(records[0]?.parserstudio_event_family,'threat');
  assert.equal(records[0]?.srcip,'192.0.2.10');
  assert.equal(records[1]?.parserstudio_event_family,'user');
  assert.equal(records[1]?.username,'김민수');
  assert.equal(records[2]?.parserstudio_event_family,'asset');
  assert.equal(records[2]?.host_name,'fw01');
  assert.equal(records[3]?.parserstudio_event_family,'threat');
  assert.equal((records[3]?.parserstudio_transport as {forwarder_hops:unknown[]}).forwarder_hops.length,1);
  assert.equal(records[4]?.parserstudio_event_family,'threat');
  assert.equal((records[4]?.parserstudio_transport as {forwarder_hops:unknown[]}).forwarder_hops.length,2);
  assert.equal(records[5]?.parser_err_stage,'extraction');
  assert.equal(records[6]?.parser_err_msg,'MappedFieldError');
  assert.equal(records[6]?.parser_err_stage,'normalization');
  assert.equal(JSON.stringify(records).includes('DO_NOT_ECHO_PRIVATE'),false);
  assert.equal(JSON.stringify(records).includes('unknown-relay fw:'),false);
});

test('offline HTTP accepts explicitly reviewed conditional parser and never enables sensor endpoints',async()=>{
  const srv=createMainlineAuthoringServer();
  await new Promise<void>(resolve=>srv.listen(0,'127.0.0.1',resolve));
  const port=(srv.address() as AddressInfo).port;
  const base='http://127.0.0.1:'+port;
  const post=async(path:string,body:unknown)=>fetch(base+path,{method:'POST',
    headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  try{
    const cap=await fetch(base+'/api/v1/parser-pairs/capabilities');
    assert.equal(cap.status,200);
    const features=await cap.json() as any;
    assert.equal(features.authoring.conditionalEventProfiles,true);
    assert.equal(features.authoring.declaredForwarderMaximumHops,3);
    assert.equal(features.verification.targetImportVerified,false);
    assert.equal(Object.hasOwn(features,'testLab'),false);

    const p=project();
    const validate=await post('/api/v1/parser-pairs/validate',p);
    assert.equal(validate.status,200);
    assert.equal((await validate.json() as any).ok,true);
    const generate=await post('/api/v1/parser-pairs/generate',p);
    assert.equal(generate.status,200);
    const pair=await generate.json() as any;
    assert.equal(pair.files.length,2);
    assert.equal(pair.manifest.status,'DRAFT');
    assert.equal(pair.manifest.targetImportVerified,false);
    const ruby=pair.files.find((f:any)=>!f.name.endsWith('.conf')).content as string;
    assert.match(ruby,/def parserstudio_unwrap_declared_relays/);
    assert.match(ruby,/def parserstudio_event_profile/);
    for(const route of ['/api/v1/test-lab/sessions/start','/api/v1/parser-pairs/target/apply']){
      const rejected=await post(route,p);
      assert.equal(rejected.status,404);
    }
    assert.equal(pair.manifest.engineVerified,false);
  }finally{
    await new Promise<void>(resolve=>srv.close(()=>resolve()));
  }
});
