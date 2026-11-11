import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {BACKEND_CAPABILITIES} from '../src/capabilities.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';
import type {ParserProject,ExportFile} from '../src/types.js';

const PROFILE='syslog_prefix_kv_leef2_implicit_tab_v1' as const;
type Source=Record<string,unknown>;
type Sample={name:string;raw:string;source:Source};
const fixture=JSON.parse(readFileSync(new URL('./fixtures/mixed-generic-profile-v1.json',import.meta.url),'utf8')) as {
  positive:Sample[];negative:Array<{name:string;raw:string}>;
};
const ruby=process.env.PARSER_NATIVE_RUBY||'ruby';
const sha256=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');

function mappedSource(source:Source):Source{
  const mapped=structuredClone(source);
  const generic=mapped.generic as Source;
  delete generic.mode;delete generic.source_raw;
  if(!Object.keys(generic).length)delete mapped.generic;
  return mapped;
}
function leaves(value:Source,prefix=''):string[]{
  return Object.entries(value).flatMap(([key,item])=>{
    const path=prefix?prefix+'.'+key:key;
    return typeof item==='string'?[path]:leaves(item as Source,path);
  });
}
function prepared():ParserProject{
  const project=sampleProject();
  project.projectId='draft-mixed_profile_v1';project.slug='mixed_profile_v1';
  project.vendor='mixed_fixture';project.product='Mixed grammar callback fixture';
  project.receiver={protocols:['udp'],port:7123,bindAddress:'127.0.0.1',
    messageLengthLimit:65536,tcpFraming:'line'};
  project.extraction={format:'generic_structural',genericStructuralProfile:PROFILE};
  project.normalization.topFields={};project.normalization.nsFields={};
  project.normalization.vendorFields={};delete project.normalization.eventProfiles;
  for(const sample of fixture.positive){
    for(const path of leaves(mappedSource(sample.source))){
      project.normalization.vendorFields[path]={normalized_name:path,data_type:'string'};
    }
  }
  project.enrichment=[];project.classification={defaultIndex:'syslog',rules:[]};
  return project;
}
function artifact(project:ParserProject):ExportFile{
  const pair=compilePair(project);
  assert.equal(pair.manifest.status,'DRAFT');
  assert.equal(pair.manifest.engineVerified,false);
  assert.equal(pair.manifest.targetImportVerified,false);
  for(const file of pair.files){
    assert.equal(file.sha256,sha256(file.content));
    assert.equal(file.bytes,Buffer.byteLength(file.content,'utf8'));
    assert.equal(pair.manifest.fileHashes[file.name],file.sha256);
  }
  const generated=pair.files.find(file=>file.name==='customized_'+project.slug);
  assert.ok(generated);
  return generated;
}

// This runs the exact generated Ruby callback. It does not load Fluentd,
// evaluate listener configuration, contact a target or raise verification flags.
function replay(file:ExportFile,events:string[]):Array<{time:number|null;record:Source|null}>{
  const program=[
    "require 'json'","require 'digest'",
    "input=JSON.parse(STDIN.read)",
    "raise 'Artifact hash mismatch' unless Digest::SHA256.hexdigest(input.fetch('source'))==input.fetch('sha256')",
    "parser_class=Class.new",
    "parser_class.class_eval(input.fetch('source'),input.fetch('name'),1)",
    "parser=parser_class.new",
    "events=input.fetch('events').map do |raw|",
    "  callbacks=[]",
    "  parser.parse(raw) { |time,record| callbacks << {'time'=>time.nil? ? nil : time.to_f,'record'=>record} }",
    "  {'rawSha256'=>Digest::SHA256.hexdigest(raw),'callbacks'=>callbacks}",
    "end",
    "STDOUT.write(JSON.generate(events))",
  ].join('\n');
  const out=spawnSync(ruby,['-e',program],{input:JSON.stringify({source:file.content,
    sha256:file.sha256,name:file.name,events}),encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
  assert.equal(out.status,0,out.stderr||String(out.error));
  const results=JSON.parse(out.stdout) as Array<{rawSha256:string;callbacks:Array<{time:number|null;record:Source|null}>}>;
  assert.equal(results.length,events.length);
  return results.map((result,index)=>{
    assert.equal(result.rawSha256,sha256(events[index]!));
    assert.equal(result.callbacks.length,1,'Each source event has one callback, including rejected events');
    return result.callbacks[0]!;
  });
}
function expected(project:ParserProject,sample:Sample):Source{
  return {parserstudio_source:sample.source,[project.vendor]:mappedSource(sample.source),
    stellar_log_index:'syslog',msg_origin:{source:project.normalization.msgOriginSource,
      category:project.normalization.msgOriginCategory,class:project.normalization.msgClass}};
}

test('combined capability is additive while the old profile advertisement remains exact',()=>{
  assert.deepEqual(BACKEND_CAPABILITIES.authoring.genericStructuralProfiles,
    ['syslog_prefix_kv','leef2_implicit_tab']);
  assert.equal(BACKEND_CAPABILITIES.authoring.genericStructuralMixedProfileV1,true);
  const project=prepared();
  assert.equal(validateProject(project).ok,true);
  const wrong=structuredClone(project);wrong.extraction.format='json';
  assert.equal(validateProject(wrong).ok,false);
  const unknown=structuredClone(project) as unknown as {extraction:{genericStructuralProfile:string}};
  unknown.extraction.genericStructuralProfile='syslog_prefix_kv_leef2_implicit_tab_v2';
  assert.equal(validateProject(unknown).ok,false);
});

for(const reverse of [false,true]){
  test('one generated artifact preserves the complete mixed source and field union in '+(reverse?'reverse':'original')+' order',()=>{
    const project=prepared();
    const samples=reverse?[...fixture.positive].reverse():fixture.positive;
    const output=replay(artifact(project),samples.map(sample=>sample.raw));
    // No timestamp is mapped, so each event carries the receive time (never nil):
    // Stellar's receivers would otherwise report it as "pattern not matched".
    assert.deepEqual(output.map(call=>call.record),samples.map(sample=>expected(project,sample)));
    for(const call of output){
      assert.equal(typeof call.time,'number');
      assert.ok(Math.abs((call.time as number)-Date.now()/1000)<60,'event time is the receive time');
    }
  });
}

test('combined generated callback retains static extraction errors without dropping malformed or unknown events',()=>{
  const output=replay(artifact(prepared()),fixture.negative.map(sample=>sample.raw));
  output.forEach((callback,index)=>assert.deepEqual(callback,{
    time:null,record:{stellar_log_index:'syslog',parser_err_msg:'ArgumentError',parser_err_stage:'extraction'},
  },fixture.negative[index]!.name));
});

test('LEEF ownership blocks an otherwise legacy-readable malformed header before a KV fallback',()=>{
  const raw=fixture.negative[0]!.raw;
  const legacy=prepared();delete legacy.extraction.genericStructuralProfile;
  assert.ok(replay(artifact(legacy),[raw])[0]!.record?.parserstudio_source,
    'This negative case must exercise an existing permissive legacy route');
  assert.deepEqual(replay(artifact(prepared()),[raw])[0],{
    time:null,record:{stellar_log_index:'syslog',parser_err_msg:'ArgumentError',parser_err_stage:'extraction'},
  });
});

test('mixed profile preserves existing V15 extraction and does not weaken normalization collision checks',()=>{
  const raw='user=analyst action=allow src=192.0.2.44 dst=198.51.100.9 policy=example';
  const project=prepared();
  const legacy=structuredClone(project);delete legacy.extraction.genericStructuralProfile;
  const expectedLegacy=replay(artifact(legacy),[raw]);
  assert.ok(expectedLegacy[0]!.record?.parserstudio_source);
  const current=replay(artifact(project),[raw]);
  // Both replays carry their own receive time; everything else must be identical.
  assert.deepEqual(current.map(call=>call.record),expectedLegacy.map(call=>call.record));
  assert.ok([...current,...expectedLegacy].every(call=>typeof call.time==='number'));
  project.normalization.topFields={
    'generic.kv.src':{normalized_name:'srcip',data_type:'ip'},
    'leef_extension.src':{normalized_name:'srcip',data_type:'ip'},
  };
  assert.ok(validateProject(project).issues.some(issue=>issue.code==='destination_collision'));
});

test('combined scalar profile survives exact Project and Recipe projection and rejects mismatched stages',()=>{
  const legacyProject=prepared();
  const recipe=recipeFromLegacyProject(legacyProject,'b'.repeat(64),2);
  assert.deepEqual(recipe.stages.find(stage=>stage.op==='parse_generic_structural'),{
    op:'parse_generic_structural',profile:PROFILE,
  });
  const request={legacyProject,recipe};
  assert.equal(validateRecipePair(request).ok,true);
  assert.deepEqual(compileRecipePair(request).files,compilePair(legacyProject).files);
  const absent=structuredClone(request);
  const stage=absent.recipe.stages.find(item=>item.op==='parse_generic_structural')!;
  if(stage.op!=='parse_generic_structural')throw new Error('Missing profile stage');
  delete stage.profile;
  assert.equal(validateRecipePair(absent).ok,false);
  const singular=structuredClone(request);
  singular.legacyProject.extraction.genericStructuralProfile='syslog_prefix_kv';
  assert.equal(validateRecipePair(singular).ok,false);
  const unknown=structuredClone(request);
  const invalid=unknown.recipe.stages.find(item=>item.op==='parse_generic_structural') as unknown as {profile:string};
  invalid.profile='syslog_prefix_kv_leef2_implicit_tab_v2';
  assert.equal(validateRecipePair(unknown).ok,false);
});
