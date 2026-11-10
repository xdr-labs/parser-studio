import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,symlinkSync,renameSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {createBuildOnceArtifact,verifyBuildOnceArtifact,CONTRACT} from './build-once-distribution.mjs';
const HEAD='a'.repeat(40),TREE='b'.repeat(40);
function put(root,path,text){
 const file=join(root,path);
 mkdirSync(dirname(file),{recursive:true});
 writeFileSync(file,text);
}
function fixtures(root){
 put(root,'package-lock.json','{"name":"web","lockfileVersion":3}\n');
 put(root,'backend/package-lock.json','{"name":"backend","lockfileVersion":3}\n');
 put(root,'runtime/multipass/semantic-policy.v1.json','{"contract":"fixture-policy"}\n');
 put(root,'runtime/multipass/multipass_preview_api.py','print("fixture")\n');
 put(root,'dist/index.html','<!doctype html><main>Fixture</main>\n');
 put(root,'dist/assets/index-abc.js','console.log("fixture")\n');
 put(root,'backend/dist/src/mainline-authoring-server.js','export const fixture=true;\n');
 put(root,'backend/dist/semantic-policy.v1.json','{"contract":"fixture-policy"}\n');
 mkdirSync(join(root,'runtime/multipass/__pycache__'));
 put(root,'runtime/multipass/__pycache__/cache.pyc','ignored binary');
}
test('build-once immutable bundle: exact source, two identical manifestations, no runtime/target truth forgery',()=>{
 const tmp=mkdtempSync(join(tmpdir(),'ps-build-once-'));
 try{
  const root=join(tmp,'source'),one=join(tmp,'once'),two=join(tmp,'twice');
  fixtures(root);
  const first=createBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE});
  const second=createBuildOnceArtifact({root,bundle:two,head:HEAD,tree:TREE});
  assert.equal(first.contract,CONTRACT);
  assert.equal(first.targetImportVerified,false);
  assert.equal(first.indexedEventVerified,false);
  assert.equal(first.fileCount,second.fileCount);
  assert.deepEqual(first,second,'bundle manifest must be deterministic');
  assert.deepEqual(readFileSync(join(one,'manifest.json')),readFileSync(join(two,'manifest.json')));
  const verified=verifyBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE});
  assert.equal(verified.sourceHead,HEAD);
  assert.equal(verified.fileCount,first.fileCount);
  assert.equal(verified.distributionSha256.length,64);
  assert.throws(()=>createBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE}),
   /BUNDLE_ALREADY_EXISTS/);
  assert.throws(()=>verifyBuildOnceArtifact({root,bundle:one,head:'c'.repeat(40),tree:TREE}),
   /SOURCE_OR_POLICY_MISMATCH/);
  put(one,'web/index.html','tampered');
  assert.throws(()=>verifyBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE}),
   /FILE_HASH_MISMATCH/);
  put(one,'web/index.html','<!doctype html><main>Fixture</main>\n');
  const manifest=JSON.parse(readFileSync(join(one,'manifest.json'),'utf8'));
  manifest.targetImportVerified=true;
  put(one,'manifest.json',JSON.stringify(manifest));
  assert.throws(()=>verifyBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE}),
   /FORGED_TARGET_PROOF/);
  put(one,'manifest.json',readFileSync(join(two,'manifest.json')));
  put(one,'backend/hidden-logic.js','unexpected');
  assert.throws(()=>verifyBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE}),
   /UNDECLARED_OR_MISSING_FILE/);
  rmSync(join(one,'backend/hidden-logic.js'));
  put(root,'package-lock.json','{"changed":true}\n');
  assert.throws(()=>verifyBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE}),
   /SOURCE_OR_POLICY_MISMATCH/);
  put(root,'package-lock.json','{"name":"web","lockfileVersion":3}\n');
  assert.equal(verifyBuildOnceArtifact({root,bundle:one,head:HEAD,tree:TREE}).fileCount,first.fileCount);
  symlinkSync(join(root,'dist/index.html'),join(root,'dist/assets/evil-link'));
  assert.throws(()=>createBuildOnceArtifact({root,bundle:join(tmp,'evil'),head:HEAD,tree:TREE}),
   /SYMLINK/);
 }finally{rmSync(tmp,{recursive:true,force:true});}
});


test('cannot distribute secrets, shadow policy, missing runtime bytes, or inflated receipt',()=>{
 const tmp=mkdtempSync(join(tmpdir(),'ps-build-once-security-'));
 try{
  const root=join(tmp,'source');
  fixtures(root);
  put(root,'backend/dist/.env','TEST_ONLY_FORBIDDEN=1');
  assert.throws(()=>createBuildOnceArtifact({
   root,bundle:join(tmp,'secret'),head:HEAD,tree:TREE,
  }),/UNSAFE_PATH/);
  rmSync(join(root,'backend/dist/.env'));
  put(root,'backend/dist/semantic-policy.v1.json','{"contract":"shadow"}\n');
  assert.throws(()=>createBuildOnceArtifact({
   root,bundle:join(tmp,'shadow'),head:HEAD,tree:TREE,
  }),/BACKEND_POLICY_DRIFT/);
  put(root,'backend/dist/semantic-policy.v1.json','{"contract":"fixture-policy"}\n');
  const bundle=join(tmp,'qualified');
  createBuildOnceArtifact({root,bundle,head:HEAD,tree:TREE});
  const manifest=readFileSync(join(bundle,'manifest.json'),'utf8');
  put(bundle,'manifest.json',' '+manifest.repeat(200));
  assert.throws(()=>verifyBuildOnceArtifact({root,bundle,head:HEAD,tree:TREE}),
   /UNSAFE_MANIFEST/);
  put(bundle,'manifest.json',manifest);
  rmSync(join(bundle,'backend/semantic-policy.v1.json'));
  assert.throws(()=>verifyBuildOnceArtifact({root,bundle,head:HEAD,tree:TREE}),
   /UNDECLARED_OR_MISSING_FILE/);
  renameSync(join(root,'dist'),join(root,'dist-backup'));
  symlinkSync(join(root,'dist-backup'),join(root,'dist'));
  assert.throws(()=>createBuildOnceArtifact({
    root,bundle:join(tmp,'source-link'),head:HEAD,tree:TREE,
  }),/SOURCE_ROOT_SYMLINK/);
 }finally{rmSync(tmp,{recursive:true,force:true});}
});
