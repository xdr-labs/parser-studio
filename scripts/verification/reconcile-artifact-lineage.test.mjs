import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyCrossJobLineage} from './reconcile-artifact-lineage.mjs';
const sha='a'.repeat(64);
const head='b'.repeat(40);
const tree='c'.repeat(40);
const correct=()=>({
  contract:'parser-studio.executable-artifact-lineage.v1',
  sourceHead:head,sourceTree:tree,worktreeDirty:false,
  sourceContractHash:sha,runtimeProfileSha256:sha,sharedMappingPolicySha256:sha,
  compilerTemplateSha256:sha,artifactSource:'fixed-public-synthetic',
  fileHashes:{customized_sample_firewall:sha,'customized_sample_firewall.conf':sha},
  artifactRevisionId:sha,packageSha256:sha,outputStatus:'DRAFT',
  reproducibleWithinBuild:true,nativeRubyExecuted:false,
  stellarTargetImportVerified:false,indexedEventVerified:false,
  userParserVerified:false,deploymentPerformed:false,
});
test('exact source, source hashes, pair, ZIP and proof-boundary agree between CI jobs',()=>{
  const r=verifyCrossJobLineage(correct(),correct(),head);
  assert.deepEqual(r,{
    contract:'parser-studio.cross-job-artifact-lineage.v1',
    result:'PASS',sourceHead:head,evidenceSources:2,sameExactOutputHashes:true,
    independentTargetRuntimeVerified:false,buildOnceDistributionVerified:false,
    stellarIndexedEventVerified:false,
  });
});
test('rejects altered source, policy, runtime profile, compiler template, Ruby/CONF, ZIP or proof claims',()=>{
  for(const [key,val] of [
    ['sourceHead','d'.repeat(40)],['sourceTree','d'.repeat(40)],
    ['sourceContractHash','d'.repeat(64)],['runtimeProfileSha256','d'.repeat(64)],
    ['sharedMappingPolicySha256','d'.repeat(64)],
    ['compilerTemplateSha256','d'.repeat(64)],
    ['artifactRevisionId','d'.repeat(64)],['packageSha256','d'.repeat(64)],
    ['worktreeDirty',true],['reproducibleWithinBuild',false],
    ['nativeRubyExecuted',true],['targetImportVerified',true],
    ['stellarTargetImportVerified',true],['indexedEventVerified',true],
    ['userParserVerified',true],['deploymentPerformed',true],
    ['artifactSource','customer'],['outputStatus','VERIFIED'],
  ]){
    const mutated=correct();mutated[key]=val;
    assert.throws(()=>verifyCrossJobLineage(correct(),mutated,head),key);
  }
  for(const key of ['customized_sample_firewall','customized_sample_firewall.conf']){
    const mutated=correct();mutated.fileHashes[key]='d'.repeat(64);
    assert.throws(()=>verifyCrossJobLineage(correct(),mutated,head),key);
  }
  const missing=correct();delete missing.fileHashes.customized_sample_firewall;
  assert.throws(()=>verifyCrossJobLineage(correct(),missing,head),'missing generated file');
});
test('fails closed with missing evidence, invalid schema, incomplete hash, stale head or extra field',()=>{
  assert.throws(()=>verifyCrossJobLineage(correct(),correct(),'wrong'));
  assert.throws(()=>verifyCrossJobLineage(null,correct(),head));
  for(const action of [
    x=>{delete x.sourceHead;},
    x=>{x.sourceHead='d'.repeat(40);},
    x=>{x.fileHashes.customized_sample_firewall='invalid';},
    x=>{x.undocumented=true;},
    x=>{x.contract='other';},
    x=>{x.sourceContractHash='';},
  ]){
    const mutated=correct();action(mutated);
    assert.throws(()=>verifyCrossJobLineage(mutated,correct(),head));
  }
});
