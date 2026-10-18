import test from 'node:test';
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
