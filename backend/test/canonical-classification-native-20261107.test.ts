import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import {CANONICAL_OPERATOR_CONTRACT_V1,evaluateCanonicalClassificationPredicate,
  supportsCanonicalClassificationOperator} from '../src/canonical-operator-contract.js';

const nativeAvailable=spawnSync('ruby',['-v'],{encoding:'utf8',timeout:3000}).status===0;

function project(equalsValue:string){
  const p=sampleProject();
  p.extraction={format:'json'};
  p.normalization.topFields={status:{normalized_name:'action',data_type:'string'}};
  p.normalization.nsFields={};
  p.normalization.vendorFields={};
  p.classification.defaultIndex='syslog';
  p.classification.rules=[{field:'action',operator:'equals',value:equalsValue,index:'threat'}];
  assert.equal(validateProject(p).ok,true);
  return p;
}

function native(projectInput:ReturnType<typeof project>,input:Record<string,unknown>):Record<string,unknown>{
  const compiled=compilePair(projectInput);
  const fragment=compiled.files.find(file=>!file.name.endsWith('.conf'))!;
  assert.match(fragment.content,/Canonical classifier contract: parser-studio\.operator-semantics\.v1/);
  const script=[
    "require 'json'","require 'base64'","require 'time'","require 'date'",
    "require 'ipaddr'","require 'csv'",
    `fragment=Base64.strict_decode64('${Buffer.from(fragment.content).toString('base64')}')`,
    "parser_class=Class.new","parser_class.class_eval(fragment)",
    "parser=parser_class.new",
    "parser.parse(STDIN.read){|_time,record|STDOUT.write(JSON.generate(record))}",
  ].join('\n');
  const run=spawnSync('ruby',['-e',script],{
    encoding:'utf8',input:JSON.stringify(input),timeout:9000,maxBuffer:1024*1024,
  });
  assert.equal(run.status,0,run.stderr||String(run.error));
  assert.ok(run.stdout.length>0,'Generated native parser emitted no event');
  return JSON.parse(run.stdout) as Record<string,unknown>;
}

test('canonical v1 specifies strict typed classification after normalization',()=>{
  assert.equal(CANONICAL_OPERATOR_CONTRACT_V1.contract,'parser-studio.operator-semantics.v1');
  assert.deepEqual([...CANONICAL_OPERATOR_CONTRACT_V1.executionOrder],
    ['extract-source','normalize-typed-fields','apply-enrichment','classify']);
  assert.equal(supportsCanonicalClassificationOperator('equals','integer'),false);
  assert.equal(supportsCanonicalClassificationOperator('equals','boolean'),false);
  assert.equal(supportsCanonicalClassificationOperator('equals','string'),true);
  assert.equal(supportsCanonicalClassificationOperator('exists','integer'),true);
  assert.equal(evaluateCanonicalClassificationPredicate('equals',6,'6'),false);
  assert.equal(evaluateCanonicalClassificationPredicate('equals','6','6'),true);
  assert.equal(evaluateCanonicalClassificationPredicate('equals','06','6'),false);
  assert.equal(evaluateCanonicalClassificationPredicate('exists',0),true);
  assert.equal(evaluateCanonicalClassificationPredicate('exists',false),true);
  assert.equal(evaluateCanonicalClassificationPredicate('exists',null),false);
  assert.equal(evaluateCanonicalClassificationPredicate('exists',undefined),false);
});

test('both generated Ruby templates embed the same canonical v1 contract marker',()=>{
  const single=compilePair(project('0006'));
  const familyProject=project('0006');
  familyProject.normalization.eventProfiles={
    discriminator:'event_type',unknown:'reject',variants:[
      {name:'firewall',equals:'firewall',topFields:familyProject.normalization.topFields,
       nsFields:{},vendorFields:{}},
      {name:'system',equals:'system',topFields:{name:{normalized_name:'username',data_type:'string'}},
       nsFields:{},vendorFields:{}},
    ],
  };
  // Keep a real event-family discriminator in the base, not a forged variant.
  familyProject.normalization.topFields={
    event_type:{normalized_name:'event_type',data_type:'string'},
  };
  familyProject.classification.rules=[];
  const familyValidation=validateProject(familyProject);
  assert.equal(familyValidation.ok,true,JSON.stringify(familyValidation.issues));
  const family=compilePair(familyProject);
  const implementations:string[]=[];
  for(const artifact of [single,family]){
    assert.equal(artifact.files.length,2);
    const fragment=artifact.files.find(file=>!file.name.endsWith('.conf'))!.content;
    assert.match(fragment,/Canonical classifier contract: parser-studio\.operator-semantics\.v1/);
    const method=fragment.match(/^def parserstudio_classify\(normalized\)[\s\S]*?^end$/m)?.[0];
    assert.ok(method,'The compiled Ruby must contain the canonical classifier method');
    implementations.push(method);
  }
  assert.equal(implementations[0],implementations[1],
    'Both generated Ruby templates must use byte-identical classification semantics');
});

test('real generated Ruby uses exact string equality, preserving leading zeros',
  {skip:!nativeAvailable},()=>{
    const p=project('0006');
    const examples:Array<[Record<string,unknown>,string]>=[
      [{status:'0006'},'threat'],
      [{status:'6'},'syslog'],
      [{status:6},'syslog'],
      [{status:null},'syslog'],
    ];
    for(const [event,index] of examples){
      const output=native(p,event);
      assert.equal(output.stellar_log_index,index,JSON.stringify(event));
    }
  });

test('real generated Ruby exists classifies typed normalized ports',
  {skip:!nativeAvailable},()=>{
    const p=project('unused');
    p.normalization.topFields={port:{normalized_name:'dstport',data_type:'port'}};
    p.classification.rules=[{field:'dstport',operator:'exists',index:'session'}];
    assert.equal(validateProject(p).ok,true);
    assert.equal(native(p,{port:443}).stellar_log_index,'session');
    assert.equal(native(p,{port:null}).stellar_log_index,'syslog');
  });

test('real generated Ruby exists counts boolean false as present',
  {skip:!nativeAvailable},()=>{
    const p=project('unused');
    p.normalization.topFields={flag:{normalized_name:'custom.flag',data_type:'boolean'}};
    p.classification.rules=[{field:'custom.flag',operator:'exists',index:'session'}];
    assert.equal(validateProject(p).ok,true);
    assert.equal(native(p,{flag:false}).stellar_log_index,'session');
    assert.equal(native(p,{flag:null}).stellar_log_index,'syslog');
  });
