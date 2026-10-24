import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';

function project(){
 const p=sampleProject();
 p.projectId='draft-mixed_csv';p.slug='mixed_csv';
 p.receiver.port=7511;
 p.extraction={format:'mixed',mixedFormats:['json','kv','csv'] as any,
   csvColumns:['src_ip','action','dst_port'],csvDelimiter:';'};
 p.normalization.topFields={
  src_ip:{normalized_name:'srcip',data_type:'ip'},
  action:{normalized_name:'action',data_type:'string'},
  dst_port:{normalized_name:'dstport',data_type:'port'},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[{field:'action',operator:'equals',value:'deny',index:'threat'}];
 return p;
}
test('explicit reviewed CSV plus JSON/KV mixes to exact ParserProject and v0.2 SHA pair',()=>{
 const p=project();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const pair=compilePair(p);
 assert.equal(pair.manifest.engineVerified,false);
 assert.equal(pair.manifest.targetImportVerified,false);
 assert.ok(pair.manifest.warnings.some(w=>w.includes('CSV columns')));
 const r=recipeFromLegacyProject(p,'c'.repeat(64),4);
 assert.deepEqual(r.stages.slice(0,2),[
  {op:'split_event',boundary:'single-line'},
  {op:'dispatch_family',families:['json','kv','csv'],mode:'strict_prefix'}
 ]);
 assert.equal(validateRecipePair({recipe:r,legacyProject:p}).ok,true);
 const staged=compileRecipePair({recipe:r,legacyProject:p});
 assert.deepEqual(staged.files,pair.files);
 assert.ok(pair.files[0]!.content.includes('port 7511'));
 for(const f of pair.files)assert.equal(f.sha256,
  createHash('sha256').update(f.content).digest('hex'));
});
test('strict mixed CSV compiles TAB safely for Ruby 3.2 while preserving the no-liberal-parsing boundary',()=>{
 const p=project();
 p.extraction={...p.extraction,csvDelimiter:'\t'};
 assert.equal(validateProject(p).ok,true);
 const pair=compilePair(p);
 const ruby=pair.files[1]!.content;
 assert.match(ruby,/CSV\.parse_line\(text, col_sep: separator, liberal_parsing: false, strip: \(separator != "\\t"\)\)/);
 assert.equal(ruby.includes('liberal_parsing: true'),false);
 assert.equal(pair.manifest.engineVerified,false);
 assert.equal(pair.manifest.targetImportVerified,false);
});
test('mixed CSV requires explicit column names/delimiter and rejects ambiguous schemas',()=>{
 const p=project();
 const errors:Array<(x:any)=>void>=[
  x=>{delete x.extraction.csvColumns;},
  x=>{delete x.extraction.csvDelimiter;},
  x=>{x.extraction.csvColumns=['src_ip'];},
  x=>{x.extraction.csvColumns=['src_ip','src_ip','action'];},
  x=>{x.extraction.csvColumns=['src_ip','__proto__','dst_port'];},
  x=>{x.extraction.csvDelimiter='|';},
  x=>{x.extraction.mixedFormats=['json','kv'];},
  x=>{x.extraction.mixedFormats=['json','csv','csv'];},
  x=>{x.extraction.mixedFormats=['json','csv','kv','cef','leef'];},
  x=>{x.extraction.mixedFormats=['json','csv_auto'];},
  x=>{x.extraction.csvColumns=['src_ip','action','dst_port'];x.extraction.format='json';},
 ];
 for(const change of errors){
  const bad:any=structuredClone(p);change(bad);
  assert.equal(validateProject(bad).ok,false,JSON.stringify(bad.extraction));
  assert.throws(()=>compilePair(bad),/Invalid parser project/);
 }
});
test('staged mixed CSV schema does not permit arbitrary operators or family ordering',()=>{
 const p=project(),r=recipeFromLegacyProject(p,'d'.repeat(64),4);
 for(const change of [
  (x:any)=>x.stages[1].families.reverse(),
  (x:any)=>x.stages[1].families.push('csv_auto'),
  (x:any)=>x.stages[1].mode='best_effort',
  (x:any)=>x.stages.splice(2,0,{op:'parse_ruby',script:'UNREVIEWED'}),
  (x:any)=>x.nativeVerified=true,
 ]){
  const bad:any=structuredClone(r);change(bad);
  assert.equal(validateRecipePair({recipe:bad,legacyProject:p}).ok,false);
  assert.throws(()=>compileRecipePair({recipe:bad,legacyProject:p}),/Invalid ParserRecipe/);
 }
});
