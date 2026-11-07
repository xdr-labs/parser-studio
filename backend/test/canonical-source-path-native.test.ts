import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';
import {CANONICAL_OPERATOR_CONTRACT_V1,resolveCanonicalSourcePath}
  from '../src/canonical-operator-contract.js';

const source=(name:string)=>readFileSync(new URL('../templates/'+name,import.meta.url),'utf8');
const method=(s:string)=>{
  const match=s.match(/^def parserstudio_lookup\(record, path, kind = nil\)\n[\s\S]*?^end$/m);
  assert.ok(match,'native parserstudio_lookup method missing');
  return match[0];
};
const templates=[
  method(source('ruby-fragment.rb.tpl')),
  method(source('ruby-forwarder-family.rb.tpl')),
];
const generatedPair=compilePair(sampleProject());
const generatedRuby=generatedPair.files.find(file=>!file.name.endsWith('.conf'));
assert.ok(generatedRuby,'generated Ruby artifact missing');
const generatedMethod=method(generatedRuby.content);
const ruby=spawnSync('ruby',['-v'],{encoding:'utf8'});
const required=process.env.PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED==='1';

type Case={id:string;record:Record<string,unknown>;path:string;
  kind?:'literal_root'|'nested';expected:{status:'value';value:unknown}|{status:'nullish'|'ambiguous'}};
const cases:Case[]=[
  {id:'flat',record:{'a.b':'literal'},path:'a.b',expected:{status:'value',value:'literal'}},
  {id:'nested',record:{a:{b:'nested'}},path:'a.b',expected:{status:'value',value:'nested'}},
  {id:'mixed',record:{a:{'b.c':'mixed'}},path:'a.b.c',expected:{status:'value',value:'mixed'}},
  {id:'numeric-zero',record:{a:{b:0}},path:'a.b',expected:{status:'value',value:0}},
  {id:'boolean-false',record:{a:{b:false}},path:'a.b',expected:{status:'value',value:false}},
  {id:'null',record:{a:null},path:'a',expected:{status:'nullish'}},
  {id:'missing',record:{a:{}},path:'a.b',expected:{status:'nullish'}},
  {id:'ambiguous-root',record:{'a.b':'flat',a:{b:'nested'}},path:'a.b',
    expected:{status:'ambiguous'}},
  {id:'ambiguous-reviewed',record:{'a.b':'flat',a:{b:'nested'}},path:'a.b',
    kind:'literal_root',expected:{status:'ambiguous'}},
  {id:'ambiguous-intermediate',record:{a:{'b.c':'mixed',b:{c:'nested'}}},
    path:'a.b.c',kind:'nested',expected:{status:'ambiguous'}},
  {id:'strict-miss',record:{'a.b':'flat'},path:'a.b',kind:'nested',
    expected:{status:'nullish'}},
  {id:'strict-hit',record:{a:{b:'nested'}},path:'a.b',kind:'nested',
    expected:{status:'value',value:'nested'}},
];

test('H1 canonical source-path contract pins strict ambiguous partitions and native template parity',()=>{
  assert.equal(CANONICAL_OPERATOR_CONTRACT_V1.sourcePaths.lookup,'all-partitions-own-keys');
  assert.equal(CANONICAL_OPERATOR_CONTRACT_V1.sourcePaths.ambiguous,'reject');
  assert.equal(templates[0],templates[1],'native variants must not diverge');
  assert.equal(generatedMethod,templates[0],'generated Ruby must retain exact reviewed lookup method');
  for(const c of cases){
    const result=resolveCanonicalSourcePath(c.record,c.path,c.kind);
    const observed=result.status==='ambiguous'?{status:'ambiguous'}:
      result.status==='missing'||result.value===null?{status:'nullish'}:
      {status:'value',value:result.value};
    assert.deepEqual(observed,c.expected,c.id);
  }
});

test('H1 actual Ruby path selection agrees with independently authored truth',
  {skip:ruby.status!==0},()=>{
    const runner=[
      "require 'json'",generatedMethod,
      "rows=JSON.parse(STDIN.read).map do |item|",
      "  begin",
      "    val=parserstudio_lookup(item.fetch('record'),item.fetch('path'),item['kind'])",
      "    val.nil? ? {'status'=>'nullish'} : {'status'=>'value','value'=>val}",
      "  rescue ArgumentError => error",
      "    raise unless error.message == 'Ambiguous source path'",
      "    {'status'=>'ambiguous'}",
      "  end",
      "end",
      "STDOUT.write(JSON.generate(rows))",
    ].join('\n');
    const result=spawnSync('ruby',['-e',runner],{
      encoding:'utf8',timeout:15000,maxBuffer:512*1024,
      input:JSON.stringify(cases.map(({record,path,kind})=>({record,path,kind}))),
    });
    assert.equal(result.status,0,result.stderr||String(result.error));
    const observed=JSON.parse(result.stdout) as unknown[];
    assert.deepEqual(observed,cases.map(c=>c.expected));
  });
test('H1 native requirement cannot be silently skipped on CI',()=>{
  if(required)assert.equal(ruby.status,0,'mandatory native ruby unavailable');
});
