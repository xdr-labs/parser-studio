import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {BACKEND_CAPABILITIES} from '../src/capabilities.js';

const fixture=JSON.parse(readFileSync(new URL('../../tests/fixtures/roadmap-syslog-prefix-kv-20261020.json',import.meta.url),'utf8')) as {
  positive:Array<{name:string;raw:string;prefix:string;kv:Record<string,string>}>;
  negative:Array<{name:string;raw:string}>;
};
const helper=readFileSync(new URL('../templates/generic-structural-helper.rb.tpl',import.meta.url),'utf8');
const ruby=process.env.PARSER_NATIVE_RUBY||'ruby';
function runRuby(raw:string,profile?:string):{ok:boolean;fields?:Record<string,unknown>}{
  const source=["require 'json'","require 'csv'","require 'base64'","require 'ipaddr'","require 'time'",helper,
    "input=JSON.parse(STDIN.read)","@parser_rule_set={'extraction'=>{'genericStructuralProfile'=>input['profile']}}",
    "begin","  fields=parserstudio_generic_structural(input.fetch('raw'))",
    "  STDOUT.write(JSON.generate({'ok'=>true,'fields'=>fields}))",
    "rescue ArgumentError","  STDOUT.write(JSON.generate({'ok'=>false}))","end"].join('\n');
  const out=spawnSync(ruby,['-e',source],{input:JSON.stringify({raw,profile}),encoding:'utf8',timeout:5000,maxBuffer:1024*1024});
  assert.equal(out.status,0,out.stderr||String(out.error));
  return JSON.parse(out.stdout);
}

test('additional generic profile is explicit in schema, capabilities and compiled project',()=>{
  const project=sampleProject();project.receiver.port=7123;
  project.extraction={format:'generic_structural',genericStructuralProfile:'syslog_prefix_kv'};
  assert.equal(validateProject(project).ok,true);
  assert.deepEqual(BACKEND_CAPABILITIES.authoring.genericStructuralProfiles,['syslog_prefix_kv','leef2_implicit_tab']);
  const pair=compilePair(project);
  assert.equal(pair.manifest.engineVerified,false);
  assert.equal(pair.manifest.targetImportVerified,false);
  assert.match(pair.files[1]!.content,/genericStructuralProfile/);
  const wrong=structuredClone(project);wrong.extraction.format='json';
  assert.equal(validateProject(wrong).ok,false);
  const unknown=structuredClone(project) as unknown as {extraction:{genericStructuralProfile:string}};
  unknown.extraction.genericStructuralProfile='unreviewed';
  assert.equal(validateProject(unknown).ok,false);
});

for(const sample of fixture.positive){
  test('Ruby dispatcher preserves explicit prefix and all KV fields: '+sample.name,()=>{
    assert.deepEqual(runRuby(sample.raw),{ok:false});
    const parsed=runRuby(sample.raw,'syslog_prefix_kv');
    assert.equal(parsed.ok,true);
    const generic=parsed.fields!.generic as Record<string,unknown>;
    assert.equal(generic.prefix,sample.prefix);
    assert.equal(generic.source_raw,sample.raw);
    assert.deepEqual(generic.kv,sample.kv);
    assert.equal((parsed.fields!.syslog as Record<string,unknown>).time_policy,'YEAR_AND_ZONE_UNKNOWN');
  });
}
for(const sample of fixture.negative){
  test('Ruby profile retains review for '+sample.name,()=>{
    assert.deepEqual(runRuby(sample.raw,'syslog_prefix_kv'),{ok:false});
  });
}
