import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';

function javaProject(){
  const p=sampleProject();
  p.projectId='draft-java_trace';
  p.slug='java_trace';
  p.receiver.protocols=['tcp'];
  p.receiver.bindAddress='127.0.0.1';
  p.receiver.port=7510;
  p.receiver.tcpFraming='blank_line_java' as never;
  p.receiver.messageLengthLimit=8192;
  p.extraction={format:'java_stacktrace' as never};
  p.normalization.topFields={
    exception_class:{normalized_name:'exception_class',data_type:'string'},
    frame_count:{normalized_name:'frame_count',data_type:'integer'},
    cause_class:{normalized_name:'cause_class',data_type:'string'},
  };
  p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[
    {field:'exception_class',operator:'equals',value:'java.lang.IllegalStateException',index:'threat'},
  ];
  return p;
}
test('P0 Java Stack Trace requires strict TCP blank-line framing, emits same port Ruby and CONF with exact v0.2 SHA',()=>{
 const p=javaProject();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const files=compilePair(p);
 const conf=files.files.find(x=>x.name.endsWith('.conf'));
 assert.ok(conf?.content.includes('port 7510'));
 assert.ok(conf?.content.includes('delimiter "\\n\\n"'));
 assert.equal(files.manifest.engineVerified,false);
 assert.equal(files.manifest.targetImportVerified,false);
 const r=recipeFromLegacyProject(p,'a'.repeat(64),2);
 assert.deepEqual(r.stages.slice(0,2),[
  {op:'split_event',boundary:'blank-line'},
  {op:'parse_java_stacktrace'},
 ]);
 assert.equal(validateRecipePair({recipe:r,legacyProject:p}).ok,true);
 const translated=compileRecipePair({recipe:r,legacyProject:p});
 assert.deepEqual(translated.files,files.files);
 assert.equal(translated.recipeReceipt.nativeUserParserVerified,false);
 for(const f of files.files)
  assert.equal(f.sha256,createHash('sha256').update(f.content).digest('hex'));
});
test('P0 Java Stack Trace never advertises UDP, inferred source framing or unbounded inputs',()=>{
 const p=javaProject();
 const invalid:Array<(p:any)=>void>=[
  x=>{x.receiver.tcpFraming='line';},
  x=>{x.receiver.tcpFraming='delimiter';x.receiver.delimiter='\n\n';},
  x=>{x.receiver.protocols=['udp'];},
  x=>{x.receiver.protocols=['udp','tcp'];},
  x=>{x.receiver.tcpFraming='blank_line_json';},
  x=>{x.extraction.format='json';},
  x=>{x.extraction.format='kv';},
  x=>{x.extraction.format='mixed';x.extraction.mixedFormats=['json','kv'];},
  x=>{x.receiver.messageLengthLimit=70000;},
  x=>{x.receiver.delimiter='^^';},
 ];
 for(const change of invalid){
   const bad:any=structuredClone(p);change(bad);
   assert.equal(validateProject(bad).ok,false,JSON.stringify(bad));
   assert.throws(()=>compilePair(bad),/Invalid parser project/);
 }
});
test('P0 staged Java Stack Trace rejects unapproved boundary, arbitrary operators and forged native claims',()=>{
 const p=javaProject(),r=recipeFromLegacyProject(p,'b'.repeat(64),2);
 const mutations:Array<(r:any)=>void>=[
  x=>{x.stages[0].boundary='single-line';},
  x=>{x.stages[1].op='parse_regex';},
  x=>{x.stages[1].command='eval';},
  x=>{x.stages[1].op='parse_json';},
  x=>{x.stages[0].boundary='auto';},
  x=>{x.nativeVerified=true;},
  x=>{x.stages.splice(1,0,{op:'execute_ruby',value:'NO'});},
 ];
 for(const change of mutations){
   const malformed:any=structuredClone(r);change(malformed);
   assert.equal(validateRecipePair({recipe:malformed,legacyProject:p}).ok,false);
   assert.throws(()=>compileRecipePair({recipe:malformed,legacyProject:p}),/Invalid ParserRecipe/);
 }
});
