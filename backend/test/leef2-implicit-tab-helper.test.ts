import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {injectHeaderGrammar} from '../src/compiler.js';
import {spawnSync} from 'node:child_process';

const fixture=JSON.parse(readFileSync(new URL('../../tests/fixtures/roadmap-leef2-implicit-tab-20261020.json',import.meta.url),'utf8')) as {
  positive:Array<{name:string;raw:string;header:Record<string,string>;extension:Record<string,string>}>;
  negative:Array<{name:string;raw:string}>;
};
const helper=injectHeaderGrammar(readFileSync(new URL('../templates/generic-structural-helper.rb.tpl',import.meta.url),'utf8'));
const ruby=process.env.PARSER_NATIVE_RUBY||'ruby';
function runRuby(raw:string,mode:'helper'|'dispatcher'='helper',profile?:string):unknown{
  const source=[
    "require 'json'","require 'csv'","require 'base64'","require 'ipaddr'","require 'time'",helper,
    "input=JSON.parse(STDIN.read)",
    "@parser_rule_set={'extraction'=>{'genericStructuralProfile'=>input['profile']}}",
    "if input['mode']=='helper'",
    "  result=parserstudio_generic_leef2_implicit_tab(input.fetch('raw'))",
    "else",
    "  begin",
    "    result=parserstudio_generic_structural(input.fetch('raw'))",
    "  rescue ArgumentError",
    "    result=nil",
    "  end",
    "end",
    "STDOUT.write(JSON.generate(result))",
  ].join('\n');
  const result=spawnSync(ruby,['-e',source],{
    input:JSON.stringify({raw,mode,profile}),encoding:'utf8',timeout:5000,maxBuffer:1024*1024,
  });
  assert.equal(result.status,0,result.stderr||String(result.error));
  return JSON.parse(result.stdout);
}

for(const sample of fixture.positive){
  test('Ruby implicit-TAB helper retains the exact source tree: '+sample.name,()=>{
    const expected={
      leef_header:sample.header,leef_extension:sample.extension,
      generic:{mode:'leef2_implicit_tab',source_raw:sample.raw},
    };
    assert.deepEqual(runRuby(sample.raw),expected);
    assert.deepEqual(runRuby(sample.raw,'dispatcher','leef2_implicit_tab'),expected);
    assert.equal(runRuby(sample.raw,'dispatcher'),null);
  });
}
for(const sample of fixture.negative){
  test('Ruby implicit-TAB helper retains review for '+sample.name,()=>{
    assert.equal(runRuby(sample.raw),null);
  });
}
