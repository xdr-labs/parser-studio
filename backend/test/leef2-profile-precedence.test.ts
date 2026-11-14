import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {injectHeaderGrammar} from '../src/compiler.js';
import {spawnSync} from 'node:child_process';

const fixture=JSON.parse(readFileSync(new URL('../../tests/fixtures/roadmap-leef2-precedence-20261020.json',import.meta.url),'utf8')) as {
  positive:Array<{name:string;raw:string;header:Record<string,string>;extension:Record<string,string>}>;
  negative:Array<{name:string;raw:string}>;
};
const helper=injectHeaderGrammar(readFileSync(new URL('../templates/generic-structural-helper.rb.tpl',import.meta.url),'utf8'));
const ruby=process.env.PARSER_NATIVE_RUBY||'ruby';
function runRuby(raw:string,profile?:string):Record<string,unknown>|null{
  const source=[
    "require 'json'","require 'csv'","require 'base64'","require 'ipaddr'","require 'time'",helper,
    "input=JSON.parse(STDIN.read)",
    "@parser_rule_set={'extraction'=>{'genericStructuralProfile'=>input['profile']}}",
    "begin",
    "  result=parserstudio_generic_structural(input.fetch('raw'))",
    "rescue ArgumentError",
    "  result=nil",
    "end",
    "STDOUT.write(JSON.generate(result))",
  ].join('\n');
  const result=spawnSync(ruby,['-e',source],{
    input:JSON.stringify({raw,profile}),encoding:'utf8',timeout:5000,maxBuffer:1024*1024,
  });
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout);
}

for(const sample of fixture.positive){
  test('selected Ruby LEEF dispatcher preserves the original field tree before legacy KV: '+sample.name,()=>{
    assert.deepEqual(runRuby(sample.raw,'leef2_implicit_tab'),{
      leef_header:sample.header,leef_extension:sample.extension,
      generic:{mode:'leef2_implicit_tab',source_raw:sample.raw},
    });
  });
}

test('the Ruby dispatcher keeps existing V15 projects without a selected profile unchanged',()=>{
  const legacy=runRuby(fixture.positive[0]!.raw);
  assert.ok(legacy);
  assert.equal((legacy.generic as {mode:string}).mode,'space_kv');
  assert.equal(legacy.leef_header,undefined);
});

for(const sample of fixture.negative){
  test('selected Ruby LEEF dispatcher refuses out-of-profile input without a legacy retry: '+sample.name,()=>{
    assert.equal(runRuby(sample.raw,'leef2_implicit_tab'),null);
  });
}
