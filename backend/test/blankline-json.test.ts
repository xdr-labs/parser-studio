import test from 'node:test';
import assert from 'node:assert/strict';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';

function project(){
 const p=sampleProject();
 p.projectId='draft-json_blanks';
 p.slug='json_blanks';
 p.receiver={...p.receiver,protocols:['tcp'],port:7501,
  bindAddress:'127.0.0.1',tcpFraming:'blank_line_json'};
 p.classification.rules=p.classification.rules.filter(x=>x.operator==='equals');
 return p;
}
test('P0 physically multiline JSON requires an explicit TCP blank-line frame, never generic guess',()=>{
 const p=project();
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const output=compilePair(p);
 assert.deepEqual(output.files.map(x=>x.name),
  ['customized_json_blanks.conf','customized_json_blanks']);
 const conf=output.files[0]!.content;
 assert.match(conf,/  @type tcp\n/);
 assert.doesNotMatch(conf,/  @type udp/);
 assert.ok(conf.includes('  delimiter "\\n\\n"'));
 assert.doesNotMatch(conf,/is_delimiter_part_of_log/);
 assert.match(conf,/  port 7501\n/);
 assert.ok(output.manifest.warnings.some(s=>s.includes(
  "Only explicitly TCP blank-line-framed JSON")));
 assert.ok(output.manifest.warnings.every(s=>!s.includes("PRIVATE")));
 assert.equal(output.manifest.engineVerified,false);
 assert.equal(output.manifest.targetImportVerified,false);
 const recipe=recipeFromLegacyProject(p,'c'.repeat(64),2);
 assert.deepEqual(recipe.stages[0],{op:'split_event',boundary:'blank-line'});
 assert.equal(validateRecipePair({recipe,legacyProject:p}).ok,true);
 assert.deepEqual(compileRecipePair({recipe,legacyProject:p}).files,output.files);
});
test('P0 blank-line JSON denies UDP, unsafe delimiter, mixed parser and lost framing metadata',()=>{
 const basis=project();
 const cases:Array<[string,(v:any)=>void]>=[
  ['udp',v=>v.receiver.protocols=['tcp','udp']],
  ['not_tcp',v=>v.receiver.protocols=['udp']],
  ['bad_format',v=>v.extraction.format='kv'],
  ['mixed',v=>{v.extraction.format='mixed';v.extraction.mixedFormats=['json','kv'];}],
  ['syslog',v=>{v.extraction.format='syslog_rfc5424';v.extraction.syslogBodyFormat='json';}],
  ['delimiter',v=>v.receiver.delimiter='|'],
  ['alternate',v=>v.receiver.tcpFraming='delimiter'],
 ];
 for(const [label,mutate] of cases){
  const p:any=structuredClone(basis);mutate(p);
  if(label==='alternate'){p.receiver.delimiter='|';}
  const result=validateProject(p);
  if(label!=='alternate')assert.equal(result.ok,false,label+JSON.stringify(result.issues));
  else assert.throws(()=>recipeFromLegacyProject(p,'c'.repeat(64),2));
 }
 const recipe=recipeFromLegacyProject(basis,'c'.repeat(64),2);
 const forged=structuredClone(recipe);
 (forged.stages[0] as any).boundary='single-line';
 assert.equal(validateRecipePair({recipe:forged,legacyProject:basis}).ok,false);
 const stale=project();stale.receiver.tcpFraming='line';
 assert.equal(validateRecipePair({recipe,legacyProject:stale}).ok,false);
});
