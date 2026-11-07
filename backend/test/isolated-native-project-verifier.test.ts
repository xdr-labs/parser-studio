import assert from 'node:assert/strict';
import test from 'node:test';
import {buildIsolatedNativeDockerArgs,createIsolatedNativeProjectVerifier}
 from '../src/isolated-native-project-verifier.js';

const digest='sha256:'+'a'.repeat(64);
const container='parser-h2-'+'b'.repeat(20);

test('H2 accepts only exact immutable image IDs and safe ephemeral container identifiers',()=>{
 for(const invalid of ['ruby:3.2','docker.io/ruby:latest','sha256:abc',
   'sha256:'+'A'.repeat(64),digest+' extra']){
   assert.throws(()=>buildIsolatedNativeDockerArgs(invalid,container),
    /NATIVE_ISOLATION_IMAGE_ID/);
 }
 for(const invalid of ['', 'dev',container+';sh','parser-h2-../../',container+'x']){
   assert.throws(()=>buildIsolatedNativeDockerArgs(digest,invalid),
    /NATIVE_ISOLATION_CONTAINER_NAME/);
 }
});

test('H2 Docker flags enforce no network, read-only root, nonroot, no capabilities and resource bounds',()=>{
 const args=buildIsolatedNativeDockerArgs(digest,container);
 assert.equal(args[0],'run');
 assert.equal(args.at(-1),digest);
 const opts=args.slice(1,-1);
 for(const pair of [
  ['--network','none'],['--read-only',undefined],['--cap-drop','ALL'],
  ['--security-opt','no-new-privileges'],['--user','65532:65532'],
  ['--memory','768m'],['--cpus','1'],['--pids-limit','64'],
  ['--ipc','none'],['--ulimit','cpu=25:25'],
  ['--ulimit','nofile=64:64'],
  ['--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777'],
  ['--name',container],
 ] as const){
   const positions=opts.flatMap((arg,i)=>arg===pair[0]?[i]:[]);
   assert.ok(positions.length>0,pair[0]);
   if(pair[1])assert.ok(positions.some(i=>opts[i+1]===pair[1]),pair[0]+' '+pair[1]);
 }
 assert.ok(opts.includes('--rm'));
 assert.ok(opts.includes('--interactive'));
 for(const forbidden of ['--privileged','--pid','host','--device','--volume','-v',
   '--mount','--publish','-p','--cap-add','--security-opt=seccomp=unconfined',
   '--network=host','--net=host']){
   assert.ok(!args.includes(forbidden),forbidden);
 }
 assert.deepEqual(args.filter(x=>x.startsWith('sha256:')),[digest]);
});

test('H2 rejects mutable runtime tags at verifier construction',()=>{
 assert.throws(()=>createIsolatedNativeProjectVerifier({
   dockerExecutable:'/usr/bin/docker',imageId:'ruby:3.2.11',
 }),/NATIVE_ISOLATION_IMAGE_ID/);
});
