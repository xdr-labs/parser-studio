import test from 'node:test';
import assert from 'node:assert/strict';
import type {AddressInfo} from 'node:net';
import {createBackendServer} from '../src/http.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {sampleProject} from './fixture.js';

async function served(fn:(base:string)=>Promise<void>){
 const server=createBackendServer();
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 try{await fn('http://127.0.0.1:'+(server.address() as AddressInfo).port);}
 finally{await new Promise<void>(r=>server.close(()=>r()));}
}
const basePath='/api/v1/parser-pairs/recipe/v0.2/';
const post=(base:string,op:string,input:unknown)=>
 fetch(base+basePath+op,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify(input)});
function project(){
 const p=sampleProject();p.projectId='draft-synthetic_recipe';
 p.classification.rules=p.classification.rules.filter(r=>r.operator==='equals');
 return {recipe:recipeFromLegacyProject(p,'b'.repeat(64),2),legacyProject:p};
}
test('P0-AP3 GET versioned schema/capabilities and POST strict compile over localhost',async()=>{
 await served(async base=>{
  const schema=await fetch(base+basePath+'schema');
  assert.equal(schema.status,200);
  assert.equal((await schema.json() as any).properties.compilerMode.const,'REVIEW_ONLY');
  const cap=await fetch(base+basePath+'capabilities');
  const capability=await cap.json() as any;
  assert.equal(cap.status,200);
  assert.equal(capability.compilerMode,'V01_EQUIVALENT_SUBSET');
  assert.equal(capability.targetImportVerified,false);
  assert.ok(capability.supportedEnvelopeParsers.includes('rfc3164_strict_no_year_or_zone'));
  assert.ok(capability.unsupported.includes('rfc3164_timestamp_inference'));
  assert.ok(capability.unsupported.includes('mixed_rfc3164_unreviewed_bodies'));
  assert.ok(!capability.unsupported.includes('mixed_csv'));
  assert.ok(capability.unsupported.includes('mixed_csv_unreviewed_schema'));
  assert.ok(!capability.unsupported.includes('multiline'));
  assert.ok(capability.unsupported.includes('multiline_unframed_generic'));
  assert.deepEqual(capability.strictMixedSingleLineFamilies,['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef','csv']);
  assert.ok(capability.supportedOperators.includes('dispatch_family'));
  assert.equal(capability.jsonBlankLineTcpFraming,true);
  assert.equal(capability.jsonBlankLineOtherTransports,false);
  assert.equal(capability.jsonBlankLineDelimiter,'LF_LF');
  assert.equal(capability.javaBlankLineTcpFraming,true);
  assert.equal(capability.javaBlankLineOtherTransports,false);
  assert.equal(capability.javaBlankLineDelimiter,'LF_LF');
  assert.equal(capability.javaStackTraceGrammar,'EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1');
  assert.ok(capability.supportedBodyParsers.includes('java_stacktrace'));
  assert.ok(capability.supportedOperators.includes('parse_java_stacktrace'));
  const req=project();
  const valid=await post(base,'validate',req);
  assert.equal(valid.status,200);
  assert.equal((await valid.json() as any).nativeUserParserVerified,false);
  const generated=await post(base,'generate',req);
  assert.equal(generated.status,200);
  const body=await generated.json() as any;
  assert.deepEqual(body.files.map((f:any)=>f.name),[
   'customized_sample_firewall.conf','customized_sample_firewall'
  ]);
  assert.equal(body.recipeReceipt.compilerMode,'V01_EQUIVALENT_SUBSET');
  assert.equal(body.recipeReceipt.nativeUserParserVerified,false);
  assert.equal(body.recipeReceipt.targetImportVerified,false);
  assert.equal(body.recipeReceipt.sourceHashVerifiedAgainstEvents,false);
  assert.equal(body.manifest.status,'DRAFT');
  const stillV01=await fetch(base+'/api/v1/parser-pairs/schema');
  assert.equal((await stillV01.json() as any).title,'Parser Studio portable ParserProject v0.1');
 });
});
test('P0-AP3 unsafe versioned requests refuse bytes, malicious fields and wrong methods without echo',async()=>{
 await served(async base=>{
  const req:any=project();
  req.recipe.stages.push({op:'execute_ruby',source:'CUSTOMER_RAW_SECRET'});
  const response=await post(base,'generate',req);
  assert.equal(response.status,422);
  const rejection=await response.text();
  assert.equal(rejection.includes('CUSTOMER_RAW_SECRET'),false);
  assert.equal(rejection.includes('files'),false);
  const wrong=await fetch(base+basePath+'validate');
  assert.equal(wrong.status,405);
  const unsupported=await fetch(base+basePath+'generate',{
   method:'POST',headers:{'content-type':'text/plain'},body:'PRIVATE_RAW_LOG'
  });
  assert.equal(unsupported.status,415);
  const bad=await fetch(base+basePath+'validate',{
   method:'POST',headers:{'content-type':'application/json'},body:'{malformed'
  });
  assert.equal(bad.status,400);
  const giant=await fetch(base+basePath+'generate',{
   method:'POST',headers:{'content-type':'application/json'},body:' '.repeat(270000)
  });
  assert.equal(giant.status,413);
  const extra:any=project();
  extra.apiKey='DO_NOT_ECHO_THIS';
  const fail=await post(base,'validate',extra);
  assert.equal(fail.status,422);
  assert.equal((await fail.text()).includes('DO_NOT_ECHO_THIS'),false);
 });
});
