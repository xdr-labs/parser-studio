import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {buildNativeProjectRunnerInput}
  from '../src/local-native-project-verifier.js';
import {prepareH2Synthetic,H2_EVENTS}
  from './h2-isolated-native-fixture.js';

const file=(name:string)=>readFileSync(new URL('../../'+name,import.meta.url),'utf8');
test('H2 isolated input is exact-source-bound, generated, fixed synthetic only',()=>{
  const prepared=prepareH2Synthetic();
  const input=buildNativeProjectRunnerInput(prepared) as Record<string,unknown>;
  assert.equal(input.contract,'parser-studio.native-project-runner-input.v0.1');
  assert.equal(input.sourceSha256,prepared.sourceSha256);
  assert.equal(input.parserSha256,prepared.parserSha256);
  assert.equal(input.confSha256,prepared.confSha256);
  assert.equal((input.events as unknown[]).length,H2_EVENTS.length);
  assert.equal('targetImportVerified' in input,false);
  assert.equal('sensorTrafficSent' in input,false);
});
test('H2 runner settings fail closed, with runtime checked in its own CI job',()=>{
  const shell=file('scripts/verification/h2-ci-isolated-runner.sh');
  const workflow=file('.github/workflows/quality.yml');
  const dockerfile=file('backend/native_isolation/Dockerfile');
  for(const required of [
    '--network none','--read-only','--cap-drop ALL',
    '--security-opt no-new-privileges','--pids-limit 64',
    '--memory 512m','--cpus 1','--user 65532:65532',
    '--tmpfs /tmp:rw,noexec,nosuid,size=16m',
  ])assert.ok(shell.includes(required),'H2 isolation option missing: '+required);
  assert.match(shell,/H2_OFFLINE_NONROOT_READONLY_PASS/);
  assert.match(shell,/H2_FIXED_SYNTHETIC_ONLY/);
  assert.doesNotMatch(shell,/--privileged\b|--network host\b|--mount\b|-v \//);
  assert.match(workflow,/native-isolated-synthetic:/);
  assert.match(workflow,/h2-ci-isolated-runner\.sh/);
  assert.match(dockerfile,/^USER 65532:65532$/m);
  assert.match(dockerfile,/^ENTRYPOINT \["ruby"/m);
  assert.match(dockerfile,/^FROM ruby:3\.2-slim-bookworm/m);
});
