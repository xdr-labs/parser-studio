import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sampleProject} from './fixture.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {
  NativeProjectVerificationError,
  prepareNativeProjectVerification,
  verifyNativeProjectReport,
} from '../src/native-project-verification.js';

const sha=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');

function candidate(){
  const project=sampleProject();
  project.projectId='draft-native_bound';
  project.classification.rules=project.classification.rules.filter(r=>r.operator==='equals');
  const source=[
    '{"source":{"ip":"192.0.2.10"},"destination":{"ip":"198.51.100.20","port":"443"},"action":"deny","event":{"id":"99"}}',
    '{"source":{"ip":"192.0.2.11"},"destination":{"ip":"198.51.100.21","port":"53"},"action":"allow","event":{"id":"100"}}',
  ].join('\n');
  const recipe=recipeFromLegacyProject(project,sha(source),2);
  return {
    contract:'parser-studio.native-project-request.v0.1' as const,
    confirmed:true as const,
    recipe,legacyProject:project,source,
    expected:[
      {eventId:'event-1',recordSha256:'1'.repeat(64),eventTimeMs:null},
      {eventId:'event-2',recordSha256:'2'.repeat(64),eventTimeMs:null},
    ],
  };
}

test('P0 native project preparation binds exact source, events and compiler-generated pair without returning a target claim',()=>{
  const prepared=prepareNativeProjectVerification(candidate());
  assert.equal(prepared.contract,'parser-studio.native-project-prepared.v0.1');
  assert.equal(prepared.sourceHashVerifiedAgainstEvents,true);
  assert.equal(prepared.sourceSha256,sha(candidate().source));
  assert.equal(prepared.eventCount,2);
  assert.deepEqual(prepared.events.map(x=>x.eventId),['event-1','event-2']);
  assert.deepEqual(prepared.events.map(x=>x.raw),candidate().source.split('\n'));
  assert.equal(prepared.files.length,2);
  assert.ok(prepared.files.every(f=>sha(f.content)===f.sha256));
  assert.equal(prepared.nativeUserParserVerified,false);
  assert.equal(prepared.targetImportVerified,false);
});

test('P0 native project preparation fails closed on stale source, count, extra fields and unconfirmed execution',()=>{
  const mutate:Array<(x:any)=>void>=[
    x=>{x.source+='\n{"action":"deny"}';},
    x=>{x.recipe.sample.sha256='a'.repeat(64);},
    x=>{x.recipe.sample.events=1;},
    x=>{x.expected.pop();},
    x=>{x.expected[0].eventId='event-9';},
    x=>{x.expected[0].recordSha256='not-a-hash';},
    x=>{x.confirmed=false;},
    x=>{x.secret='DO_NOT_ECHO';},
  ];
  for(const fn of mutate){
    const value:any=structuredClone(candidate());fn(value);
    assert.throws(()=>prepareNativeProjectVerification(value),NativeProjectVerificationError);
    try{prepareNativeProjectVerification(value);}catch(error){
      assert.equal(String(error).includes('DO_NOT_ECHO'),false);
      assert.equal(String(error).includes('192.0.2.10'),false);
    }
  }
});

test('P0 native project report validation only accepts source/pair-bound redacted PASS evidence',()=>{
  const p=prepareNativeProjectVerification(candidate());
  const report={
    contract:'parser-studio.native-project-verification.v0.1',
    sourceSha256:p.sourceSha256,recipeSha256:p.recipeSha256,
    parserSha256:p.parserSha256,confSha256:p.confSha256,
    eventCount:2,eventsPassed:2,recordHashMatches:2,eventTimeMatches:2,
    ruby:'3.2',fluentd:'1.17.1',confAstVerified:true,parserCallbackVerified:true,
    sourceHashVerifiedAgainstEvents:true,nativeUserParserVerified:true,
    targetImportVerified:false,sensorTrafficSent:false,rawValuesReturned:false,
  };
  assert.deepEqual(verifyNativeProjectReport(report,p),report);
  for(const changed of [
    {...report,sourceSha256:'f'.repeat(64)},
    {...report,eventsPassed:1},
    {...report,recordHashMatches:1},
    {...report,eventTimeMatches:1},
    {...report,targetImportVerified:true},
    {...report,rawValuesReturned:true},
  ]) assert.throws(()=>verifyNativeProjectReport(changed,p),NativeProjectVerificationError);
});
