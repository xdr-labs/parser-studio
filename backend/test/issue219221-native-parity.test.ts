import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import type {ParserProject} from '../src/types.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function native(project:ParserProject,raws:string[]):Record<string,unknown>[]{
  const result=compilePair(project);
  const ruby=result.files.find(file=>!file.name.endsWith('.conf'))!.content;
  const code=[
    "require 'json'","require 'base64'","require 'time'","require 'date'","require 'ipaddr'","require 'csv'",
    'input=JSON.parse(STDIN.read)',
    'klass=Class.new',
    "klass.class_eval(Base64.strict_decode64(input.fetch('fragment')))",
    'parser=klass.new',
    'results=[]',
    "input.fetch('lines').each{|line|parser.parse(line){|_time,event|results << event}}",
    'STDOUT.write(JSON.generate(results))',
  ].join('\n');
  // Large generated Ruby fragments can exceed OS argument limits when passed
  // via ruby -e. Keep the fixed script short; send the fragment via stdin.
  assert.ok(code.length < 4096, 'Ruby -e argument must remain bounded');
  const response=spawnSync('ruby',['-e',code],{
    input:JSON.stringify({fragment:Buffer.from(ruby).toString('base64'),lines:raws}),
    encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});
  assert.equal(response.status,0,response.stderr||String(response.error));
  const actual=JSON.parse(response.stdout) as Record<string,unknown>[];
  assert.equal(actual.length,raws.length);
  return actual;
}

for(const family of [false,true]){
  test('Issue #219: native '+(family?'conditional':'standard')+' Ruby preserves JS numeric-to-string semantics',
    {skip:!rubyAvailable},()=>{
      const p=sampleProject();
      const mapped={value:{normalized_name:'custom.text_value',data_type:'string' as const}};
      p.normalization.topFields={};
      p.normalization.nsFields={};
      p.normalization.vendorFields=mapped;
      p.classification.rules=[];
      if(family){
        p.normalization.topFields={event_type:{normalized_name:'event_type',data_type:'string'}};
        p.normalization.vendorFields={};
        p.normalization.eventProfiles={
          discriminator:'event_type',unknown:'reject',variants:[
            {name:'security',equals:'security',topFields:{},nsFields:{},vendorFields:mapped},
            {name:'other',equals:'other',topFields:{},nsFields:{},vendorFields:{}},
          ],
        };
      }
      const verdict=validateProject(p);
      assert.equal(verdict.ok,true,JSON.stringify(verdict.issues));
      const raws=['6.0','6e0','1e3','1e-6','-0.0','1e20'].map(value=>
        '{"value":'+value+(family?',"event_type":"security"':'')+'}');
      const results=native(p,raws);
      results.forEach((row,index)=>{
        const expected=String((JSON.parse(raws[index]!) as {value:number}).value);
        assert.equal((row.Synthetic as any)?.custom?.text_value,expected,
          JSON.stringify({raw:raws[index],row}));
        assert.equal(row.parser_err_stage,undefined,raws[index]);
      });
    });
}

test('Issue #220: native comma/semicolon CSV retains Unicode edge whitespace',
  {skip:!rubyAvailable},()=>{
    const characters=[String.fromCharCode(0xa0),String.fromCharCode(0x2003),
      String.fromCharCode(0x202f),String.fromCharCode(0xfeff)];
    for(const delimiter of [',',';'] as const){
      const p=sampleProject();
      p.extraction={format:'csv',csvColumns:['device','action_value','target'],csvDelimiter:delimiter};
      p.normalization.topFields={};
      p.normalization.nsFields={};
      p.normalization.vendorFields={
        action_value:{normalized_name:'custom.action_value',data_type:'string'},
      };
      p.classification.rules=[];
      assert.equal(validateProject(p).ok,true,delimiter);
      const raw=characters.map(space=>['node',space+'deny','fw01'].join(delimiter));
      const results=native(p,raw);
      results.forEach((row,i)=>{
        assert.equal((row.Synthetic as any)?.custom?.action_value,characters[i]+'deny',
          JSON.stringify({delimiter,row}));
      });
    }
  });

test('Issue #221: native Generic Structural drops synthetic raw copy but preserves manufacturer KV source_raw',
  {skip:!rubyAvailable},()=>{
    const p=sampleProject();
    p.receiver.port=6801;
    p.extraction={format:'generic_structural',omitSourceRaw:true};
    p.normalization.topFields={'generic.kv.user':{normalized_name:'username',data_type:'string'}};
    p.normalization.nsFields={};
    p.normalization.vendorFields={};
    p.classification.rules=[];
    const verdict=validateProject(p);
    assert.equal(verdict.ok,true,JSON.stringify(verdict.issues));
    const raw='<134>date=2023-02-23 time=22:49:29 devname=FMG-VM log_id=0001010018 type=event user=alice source_raw=vendor-specific-value status=success';
    const row=native(p,[raw])[0]!;
    const source=row.parserstudio_source as {generic:{source_raw?:string;kv:Record<string,unknown>}};
    assert.equal(source.generic.source_raw,undefined);
    assert.equal(source.generic.kv.source_raw,'vendor-specific-value');
    assert.equal(row.username,'alice');
    assert.equal(row.parser_err_stage,undefined);
  });
