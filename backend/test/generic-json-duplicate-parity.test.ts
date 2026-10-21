import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function compile(){
  const p=sampleProject();
  p.extraction={format:'generic_structural'};
  p.normalization.topFields={};
  p.normalization.nsFields={};
  p.normalization.vendorFields={
    'generic.prefix':{normalized_name:'prefix',data_type:'string'},
  };
  p.classification={defaultIndex:'syslog',rules:[]};
  // No source values embedded in the output. Test the native parser's
  // actual bounded extraction, not an unqualified browser-only preview.
  return compilePair(p).files.find(f=>!f.name.endsWith('.conf'))!.content;
}
test('compiled Generic Structural prefixed JSON uses the same strict native JSON source contract',()=>{
  const ruby=compile();
  assert.match(ruby,/def parserstudio_json_duplicate_keys\?\(raw\)/);
  assert.match(ruby,/def parserstudio_generic_prefixed_json\(text\)/);
  assert.match(ruby,/body = parserstudio_json_object\(match\[2\]\)/);
});
test('native compiled Generic Structural refuses duplicate prefixed JSON without mutating the original',
 {skip:!rubyAvailable},()=>{
  const ruby=compile();
  const cases:Array<{method:'prefixed'|'rfc5424';source:string;accepted:boolean}>=[
    {method:'prefixed',source:'vendor_test {"a":1,"a":2}',accepted:false},
    {method:'prefixed',source:'vendor_test {"left":{"k":1},"right":{"k":2}}',accepted:true},
    {method:'prefixed',source:'vendor_test {"\\u0061":1,"a":2}',accepted:false},
    {method:'rfc5424',source:'<134>1 2026-10-21T00:01:02Z gateway {"a":1,"a":2}',accepted:false},
    {method:'rfc5424',source:'<134>1 2026-10-21T00:01:02Z gateway {"left":{"k":1},"right":{"k":2}}',accepted:true},
  ];
  const statements=[
    "require 'json'","require 'base64'","require 'csv'","require 'ipaddr'","require 'time'",
    'klass=Class.new',
    "klass.class_eval(Base64.strict_decode64('"+Buffer.from(ruby,'utf8').toString('base64')+"'))",
    'parser=klass.new',
    'results=[]',
    'JSON.parse(STDIN.read).each do |entry|',
    "  method=entry['method']=='prefixed' ? :parserstudio_generic_prefixed_json : :parserstudio_generic_short_rfc5424_json",
    "  parsed=parser.send(method,entry['source'])",
    '  results << (!parsed.nil?)',
    'end',
    'STDOUT.write(JSON.generate(results))',
  ].join('\n');
  const result=spawnSync('ruby',['-e',statements],{
    input:JSON.stringify(cases),encoding:'utf8',timeout:10000,
  });
  assert.equal(result.status,0,result.stderr||String(result.error));
  assert.deepEqual(JSON.parse(result.stdout),cases.map(item=>item.accepted));
});
