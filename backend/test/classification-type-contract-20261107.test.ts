import assert from 'node:assert/strict';
import test from 'node:test';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';

for(const type of ['integer','boolean','port'] as const){
 test('native project rejects string equality against '+type+' normalized field',()=>{
  const p=sampleProject();p.normalization.topFields={value:{normalized_name:'custom.value',data_type:type}};
  p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[{field:'custom.value',operator:'equals',value:'6',index:'threat'}];
  const checked=validateProject(p);
  assert.equal(checked.ok,false);
  assert.ok(checked.issues.some(x=>x.code==='classification_type'));
 });
}
test('string-valued classifier remains valid and compiles',()=>{
 const p=sampleProject();p.normalization.topFields={value:{normalized_name:'custom.value',data_type:'string'}};
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[{field:'custom.value',operator:'equals',value:'6',index:'threat'}];
 assert.equal(validateProject(p).ok,true);
 assert.equal(compilePair(p).files.length,2);
});
