// Owner policy D-2 (decided 2026-11-14), generated Ruby. A newly created Generic Structural parser
// (extraction.genericStructuralFamilyGrammar "dedicated") reads a line that claims to be CEF or LEEF with
// the CEF/LEEF grammar or declines it; a project without the marker keeps its V15 output. The lines and the
// expected fields are the Semantic Oracle's (contracts/semantic-goldens.v1.json, ownerPolicies.D-2), so the
// browser test src/ownerPolicyD2GenericFamilies20261114.test.ts and this test hold the same expectations.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {compilePair,validateProject,BACKEND_CAPABILITIES} from '../src/index.js';
import {sampleProject} from './fixture.js';

interface GenericCase{id:string;raw:string;familyGrammar?:'dedicated';expect:{fields?:Record<string,unknown>;reject?:boolean}}
const cases=(JSON.parse(readFileSync(new URL('../../contracts/semantic-goldens.v1.json',import.meta.url),'utf8')) as
  {genericCases:GenericCase[]}).genericCases.filter(item=>item.id.startsWith('generic-d2-'));
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

function project(familyGrammar?:unknown):any{
  const p:any=sampleProject();
  p.receiver.port=6801;
  p.extraction={format:'generic_structural',...(familyGrammar===undefined?{}:{genericStructuralFamilyGrammar:familyGrammar})};
  p.normalization.topFields={};
  p.normalization.nsFields={};
  p.normalization.vendorFields={'generic.mode':{normalized_name:'d2_mode',data_type:'string'}};
  p.classification.rules=[];
  return p;
}
const fragment=(p:unknown)=>compilePair(p).files.find(file=>!file.name.endsWith('.conf'))!;

function native(p:unknown,raws:string[]):Record<string,unknown>[]{
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
  const response=spawnSync('ruby',['-e',code],{
    input:JSON.stringify({fragment:Buffer.from(fragment(p).content).toString('base64'),lines:raws}),
    encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});
  assert.equal(response.status,0,response.stderr||String(response.error));
  const actual=JSON.parse(response.stdout) as Record<string,unknown>[];
  assert.equal(actual.length,raws.length);
  return actual;
}
const deepGet=(value:unknown,path:string):unknown=>path.split('.').reduce<unknown>((node,key)=>
  node!==null&&typeof node==='object'?(node as Record<string,unknown>)[key]:undefined,value);

test('the oracle goldens cover the legacy route, the dedicated grammar and declined claims',()=>{
  assert.ok(cases.filter(item=>!item.familyGrammar&&item.expect.fields).length>=4);
  assert.ok(cases.filter(item=>item.familyGrammar==='dedicated'&&item.expect.fields).length>=4);
  assert.ok(cases.filter(item=>item.familyGrammar==='dedicated'&&item.expect.reject).length>=4);
});

for(const [route,marker] of [['legacy route (no marker)',undefined],['dedicated grammar','dedicated']] as const){
  test('owner policy D-2, generated Ruby, '+route,{skip:!rubyAvailable},()=>{
    const selected=cases.filter(item=>item.familyGrammar===marker);
    const rows=native(project(marker),selected.map(item=>item.raw));
    selected.forEach((item,index)=>{
      const row=rows[index]!;
      if(item.expect.reject){
        // Declined: an extraction error record with no parsed field, never a parsed event.
        assert.equal(row.parser_err_stage,'extraction',item.id+' was emitted as a parsed event');
        assert.equal(row.parserstudio_source,undefined,item.id);
        assert.equal(row.d2_mode,undefined,item.id);
        return;
      }
      assert.equal(row.parser_err_stage,undefined,item.id+' '+JSON.stringify(row).slice(0,200));
      for(const [path,want] of Object.entries(item.expect.fields??{}))
        assert.deepEqual(deepGet(row.parserstudio_source,path),want,item.id+' '+path);
    });
  });
}

test('the same line: the legacy route keeps the V15 tree, the dedicated grammar reads the CEF header',{skip:!rubyAvailable},()=>{
  const raw='CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=80 act=blocked proto=tcp';
  assert.deepEqual(native(project(),[raw])[0]!.parserstudio_source,{generic:{mode:'space_kv',source_raw:raw,
    kv:{dst:'2.1.2.2',spt:'1232',dpt:'80',act:'blocked',proto:'tcp'},
    prefix_001:'CEF:0|Security|threatmanager|1.0|100|worm',prefix_002:'successfully',prefix_003:'stopped|10|src=10.0.0.1'}});
  assert.deepEqual(native(project('dedicated'),[raw])[0]!.parserstudio_source,{
    body:{cef_version:'0',cef_device_vendor:'Security',cef_device_product:'threatmanager',cef_device_version:'1.0',
      cef_signature_id:'100',cef_name:'worm successfully stopped',cef_severity:'10',
      src:'10.0.0.1',dst:'2.1.2.2',spt:'1232',dpt:'80',act:'blocked',proto:'tcp'},
    generic:{mode:'structured_family_cef',source_raw:raw}});
});

test('the marker is validated, advertised, and changes the artifact only when it is set',()=>{
  assert.equal(validateProject(project('dedicated')).ok,true,JSON.stringify(validateProject(project('dedicated'))));
  assert.equal(validateProject(project()).ok,true);
  // Any other value is refused by the project schema (const "dedicated").
  for(const wrong of ['legacy',true,''])assert.equal(validateProject(project(wrong)).ok,false,String(wrong));
  // The marker on another extraction format is refused by the validator.
  const other:any=sampleProject();
  other.extraction.genericStructuralFamilyGrammar='dedicated';
  const verdict=validateProject(other);
  assert.equal(verdict.ok,false);
  assert.ok(verdict.issues.some(issue=>issue.code==='generic_structural_family_grammar'),JSON.stringify(verdict.issues));
  assert.equal((BACKEND_CAPABILITIES.authoring as any).genericStructuralDedicatedFamilies,true);
  assert.notEqual(fragment(project()).sha256,fragment(project('dedicated')).sha256);
  assert.equal(fragment(project()).sha256,fragment(project()).sha256);
});
