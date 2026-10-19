import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {prepareNativeProjectVerification} from '../src/native-project-verification.js';
import {buildNativeProjectRunnerInput,createLocalNativeProjectVerifier}
  from '../src/local-native-project-verifier.js';

const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
function prepared(){
 const project=sampleProject();project.projectId='draft-native_local';
 project.classification.rules=project.classification.rules.filter(r=>r.operator==='equals');
 const source='{"action":"deny","source":{"ip":"192.0.2.10"},"destination":{"port":"443"}}';
 return prepareNativeProjectVerification({
  contract:'parser-studio.native-project-request.v0.1',confirmed:true,
  recipe:recipeFromLegacyProject(project,sha(source),1),legacyProject:project,source,
  expected:[{eventId:'event-1',recordSha256:'1'.repeat(64),eventTimeMs:null}],
 });
}
test('local Native runner input is constructed only from compiler-prepared pair and source-bound events',()=>{
 const p=prepared();
 const input=buildNativeProjectRunnerInput(p) as any;
 assert.deepEqual(Object.keys(input).sort(),[
  'confName','confSha256','confSource','contract','events','parserName','parserSha256',
  'parserSource','receiver','recipeSha256','sourceSha256',
 ].sort());
 assert.equal(input.parserSource,p.files.find(x=>x.name===p.parserName)?.content);
 assert.equal(input.confSource,p.files.find(x=>x.name===p.confName)?.content);
 assert.equal(input.events[0].raw,p.events[0]?.raw);
 assert.equal(input.targetImportVerified,undefined);
});
test('local Native verifier configuration fails closed before process launch',async()=>{
 assert.throws(()=>createLocalNativeProjectVerifier({
  rubyExecutable:'/bin/false',wallTimeoutMs:31_000,
 }),/NATIVE_PROJECT_RUNTIME_LIMIT/);
 const verifier=createLocalNativeProjectVerifier({rubyExecutable:'ruby'});
 await assert.rejects(()=>verifier.verify(prepared()),/NATIVE_PROJECT_RUNTIME_PATH/);
 const polluted=createLocalNativeProjectVerifier({
  rubyExecutable:'/bin/false',environment:{API_KEY:'never-pass-through'},
 });
 await assert.rejects(()=>polluted.verify(prepared()),/NATIVE_PROJECT_RUNTIME_ENV|NATIVE_PROJECT_RUNTIME_PATH/);
});
