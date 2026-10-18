import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import type {AddressInfo} from 'node:net';
import {createBackendServer,type BackendServerOptions} from '../src/http.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {sampleProject} from './fixture.js';
import type {NativeProjectPrepared} from '../src/native-project-verification.js';

const sha=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
const path='/api/v1/parser-pairs/recipe/v0.2/native-verify';

function request(){
 const project=sampleProject();
 project.projectId='draft-native_http';
 project.classification.rules=project.classification.rules.filter(r=>r.operator==='equals');
 const source='{"source":{"ip":"192.0.2.10"},"destination":{"ip":"198.51.100.20","port":"443"},"action":"deny","event":{"id":"99"}}';
 return {
  contract:'parser-studio.native-project-request.v0.1',confirmed:true,
  recipe:recipeFromLegacyProject(project,sha(source),1),legacyProject:project,source,
  expected:[{eventId:'event-1',recordSha256:'1'.repeat(64),eventTimeMs:null}],
 };
}
function pass(prepared:NativeProjectPrepared){
 return {
  contract:'parser-studio.native-project-verification.v0.1',
  sourceSha256:prepared.sourceSha256,recipeSha256:prepared.recipeSha256,
  parserSha256:prepared.parserSha256,confSha256:prepared.confSha256,
  eventCount:prepared.eventCount,eventsPassed:prepared.eventCount,
  recordHashMatches:prepared.eventCount,eventTimeMatches:prepared.eventCount,
  ruby:'3.2',fluentd:'1.17.1',confAstVerified:true,parserCallbackVerified:true,
  sourceHashVerifiedAgainstEvents:true,nativeUserParserVerified:true,
  targetImportVerified:false,sensorTrafficSent:false,rawValuesReturned:false,
 };
}
async function served(options:BackendServerOptions,fn:(base:string)=>Promise<void>){
 const server=createBackendServer(options);
 await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{await fn('http://127.0.0.1:'+(server.address() as AddressInfo).port);}
 finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}
const post=(base:string,body:unknown)=>fetch(base+path,{
 method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),
});

test('P0 per-project Native HTTP is disabled before body parsing and capability stays truthful',async()=>{
 await served({},async base=>{
  const denied=await fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:'{bad'});
  assert.equal(denied.status,403);
  assert.deepEqual(await denied.json(),{error:'NATIVE_PROJECT_VERIFY_DISABLED'});
  const caps=await fetch(base+'/api/v1/parser-pairs/recipe/v0.2/capabilities');
  const body=await caps.json() as any;
  assert.equal(body.nativeProjectVerificationConfigured,false);
  assert.equal(body.nativeProjectVerificationRequiresAuth,true);
  assert.equal(body.nativeUserParserVerified,false);
  assert.equal(body.targetImportVerified,false);
 });
});

test('P0 authorized Native HTTP receives only compiler-generated prepared pair and returns redacted bound PASS',async()=>{
 let preparedSeen:NativeProjectPrepared|undefined;
 await served({nativeProjectVerifier:{
  authorize:async()=>true,
  verify:async prepared=>{preparedSeen=prepared;return pass(prepared);},
 }},async base=>{
  const response=await post(base,request());
  assert.equal(response.status,200);
  const text=await response.text();
  assert.equal(text.includes('192.0.2.10'),false);
  assert.equal(text.includes('198.51.100.20'),false);
  const body=JSON.parse(text);
  assert.equal(body.nativeUserParserVerified,true);
  assert.equal(body.targetImportVerified,false);
  assert.equal(body.sensorTrafficSent,false);
  assert.equal(body.rawValuesReturned,false);
  assert.equal(preparedSeen?.nativeUserParserVerified,false);
  assert.equal(preparedSeen?.targetImportVerified,false);
  assert.equal(preparedSeen?.files.length,2);
  assert.equal(preparedSeen?.events.length,1);
  assert.equal(preparedSeen?.events[0]?.raw,request().source);
  assert.ok(preparedSeen?.files.every(f=>sha(f.content)===f.sha256));
 });
});

test('P0 Native HTTP denies unauthenticated, malformed/stale input and forged verifier reports without echo',async()=>{
 let calls=0;
 await served({nativeProjectVerifier:{
  authorize:async req=>req.headers.authorization==='Bearer allowed',
  verify:async prepared=>{calls++;return pass(prepared);},
 }},async base=>{
  const unauth=await post(base,request());
  assert.equal(unauth.status,403);
  assert.equal(calls,0);

  const forged:any=request();forged.confirmed=false;forged.secret='PRIVATE_NATIVE_VALUE';
  const invalid=await fetch(base+path,{method:'POST',
   headers:{'content-type':'application/json','authorization':'Bearer allowed'},
   body:JSON.stringify(forged)});
  assert.equal(invalid.status,422);
  const invalidText=await invalid.text();
  assert.equal(invalidText.includes('PRIVATE_NATIVE_VALUE'),false);
  assert.equal(invalidText.includes('192.0.2.10'),false);
  assert.equal(calls,0);
 });
 await served({nativeProjectVerifier:{
  authorize:async()=>true,
  verify:async prepared=>({...pass(prepared),targetImportVerified:true}),
 }},async base=>{
  const forged=await post(base,request());
  assert.equal(forged.status,503);
  const body=await forged.json() as any;
  assert.equal(body.error,'NATIVE_PROJECT_VERIFY_UNAVAILABLE');
  assert.equal(body.nativeUserParserVerified,false);
  assert.equal(body.targetImportVerified,false);
 });
});

test('P0 Native HTTP rejects method/media/oversize before verifier execution',async()=>{
 let calls=0;
 await served({nativeProjectVerifier:{
  authorize:async()=>true,verify:async prepared=>{calls++;return pass(prepared);},
 }},async base=>{
  assert.equal((await fetch(base+path)).status,405);
  assert.equal((await fetch(base+path,{method:'POST',headers:{'content-type':'text/plain'},body:'x'})).status,415);
  const huge=' '.repeat(449*1024);
  assert.equal((await fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:huge})).status,413);
  assert.equal(calls,0);
 });
});
