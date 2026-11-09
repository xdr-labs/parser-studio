/**
 * Executable architecture gate: prevents accidental shadow semantics and
 * mixed-HEAD E2E certification. Does NOT claim DP import or a formally proven
 * time bound for native Regexp. All validation uses source-only metadata.
 */
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
const text=(path)=>readFileSync(path,'utf8');
const json=(path)=>JSON.parse(text(path));
const policy=json('runtime/multipass/semantic-policy.v1.json');
const coverage=json('contracts/execution-coverage.v1.json');
const matrix=json('contracts/executable-capability-matrix.v1.json');
const profiles=json('contracts/target-runtime-profiles.v1.json');

function validateCanonicalPolicy(input){
  assert.equal(input.contract,'parser-studio.semantic-policy.v1');
  const aliases=input.normalizationAliases;
  const advisory=input.advisoryOnlyAliases;
  const allowed=input.advisoryNameOnlySources;
  const types=input.advisoryTargetTypes;
  assert.ok(Object.keys(aliases).length>=90);
  for(const [source,target] of Object.entries(input.explicitPortSourceAliases)){
    assert.equal(aliases[source],target,'explicit ports must share browser semantics');
  }
  for(const required of ['source-port','destination-port','srcport','dstport','srcip','dstip']){
    assert.ok(allowed.includes(required),'missing mandatory name-only identity '+required);
  }
  assert.equal(new Set(allowed).size,allowed.length);
  for(const source of allowed){
    const dest=aliases[source]??advisory[source];
    assert.ok(dest,'unowned advisory alias '+source);
    assert.ok(['ip','port','string'].includes(types[dest]),
      'advisory target needs a reviewed type: '+source);
  }
}
function validateNativeProfiles(input){
  assert.equal(input.contract,'parser-studio.target-runtime-profiles.v1');
  const ruby32=input.profiles.find(p=>p.id==='ci-synthetic-ruby32');
  const ruby24=input.profiles.find(p=>p.id==='stellar70-observed-ruby24');
  assert.equal(ruby32?.ruby,'3.2.11');
  assert.equal(ruby32?.fluentd,'1.17.1');
  assert.equal(ruby32?.targetIndexedEventVerified,false);
  assert.equal(ruby24?.ruby,'2.4.9');
  assert.match(ruby24?.ciContainerImage??'',/^ruby:2\.4\.9@sha256:[0-9a-f]{64}$/);
  assert.equal(ruby24?.fluentd,'1.7.4');
  assert.equal(ruby24?.regexDeadlineCapable,false);
  assert.equal(input.targetVerified,false);
  for(const feature of ['regex','syslog-regex-body']){
    assert.ok(input.unsupported.some(f=>f.feature===feature&&
      f.profile===ruby24.id&&f.behavior==='FAIL_CLOSED_RUNTIME'),
      'unsupported Ruby2.4 regex cannot be misreported as safe');
  }
}
validateCanonicalPolicy(policy);
validateNativeProfiles(profiles);
const shipping=json('contracts/shipping-surface.v1.json');
assert.equal(shipping.contract,'parser-studio.shipping-surface.v1');
assert.equal(shipping.legacyOnlyHttp.mainlineReachable,false);
assert.ok(existsSync('scripts/verification/shipping-entrypoint-reachability.mjs'));
assert.equal(matrix.contract,'parser-studio.executable-capability-matrix.v1');
assert.equal(matrix.independentSemanticCaseCount,26);
assert.ok(existsSync(matrix.independentSemanticOracle));
assert.ok(existsSync(matrix.independentSemanticOracleTruth));
const independent=json(matrix.independentSemanticOracleTruth);
assert.equal(independent.oracleOrigin,'INDEPENDENTLY_AUTHORED_EXPECTED_TARGETS');
assert.equal(independent.cases.length,matrix.independentSemanticCaseCount);
assert.equal(independent.targetIndexedProof,false);
assert.equal(matrix.independentRuntimeProof,false);
assert.equal(matrix.stellar7IndexedProof,false);
assert.deepEqual(
  Object.keys(matrix.formatOraclePaths).sort(),
  [...coverage.extractionFormats].sort(),
  'every advertised extraction grammar needs a declared native oracle');
for(const file of Object.values(matrix.formatOraclePaths))
  assert.ok(existsSync(file),'missing format oracle '+file);
for(const c of matrix.consumers){
  assert.ok(existsSync(c.source),'missing consumer '+c.id);
  assert.ok(existsSync(c.oracle),'missing oracle '+c.id);
  if(c.policy)assert.ok(existsSync(c.policy),'missing policy '+c.id);
  assert.equal(c.targetVerified,false);
}
assert.equal(matrix.consumers.find(c=>c.id==='backend-advisory-hints')?.shippingMainlineRoute,false);
assert.match(text('backend/src/mainline-authoring-server.ts'),/deterministicNameOnlyMappingHttpAvailable:false/);
for(const id of [
  'browser-normalization','python-multipass','backend-advisory-hints',
  'ruby-pair-compiler','browser-http-authoring',
])assert.ok(matrix.consumers.some(c=>c.id===id));
assert.deepEqual(
  readFileSync('backend/semantic-policy.v1.json'),
  readFileSync('runtime/multipass/semantic-policy.v1.json'),
  'backend policy snapshot must be byte-for-byte canonical');
assert.match(text('src/guided/normalizationCandidates.ts'),
  /semanticPolicy\.normalizationAliases/);
assert.match(text('backend/src/mapping-suggestions.ts'),
  /semanticPolicy\.normalizationAliases/);
assert.doesNotMatch(text('backend/src/mapping-suggestions.ts'),
  /const aliases\s*:/);
assert.match(text('runtime/multipass/stellar_dictionary.py'),
  /semantic-policy\.v1\.json/);
assert.ok(existsSync('scripts/verification/mapping-hints-cross-consumer.ts'));
assert.match(text('.github/workflows/quality.yml'),/MAPPING_CROSS_CONSUMER_PARITY_PASS|mapping-hints-cross-consumer\.ts/);
assert.match(text('backend/src/compiler.ts'),/Regexp\.respond_to\?\(:timeout=\)/);
assert.match(text('backend/src/compiler.ts'),/Native Regex unsupported/);
const workflow=text('.github/workflows/quality.yml');
assert.match(workflow,/H4_RELEASE_ELIGIBILITY_NOT_EVALUATED_ON_PR/);
assert.match(workflow,/GITHUB_EVENT_NAME.*pull_request/);
assert.match(workflow,/for label in P0 P1/);
assert.doesNotMatch(workflow,/ref: 03624952a8c097e5423df32b40ec64137f029f49/);
assert.match(workflow,/PARSER_STUDIO_BACKEND_HEAD: \$\{\{ github\.sha \}\}/);
assert.match(text('playwright.config.ts'),/liveBackend&&actual!==frontendHead/);
assert.doesNotMatch(workflow,/--grep-invert /);
// Assert a deliberately corrupted contract is detected by the same
// function used on actual source (without mutating repository files).
for(const mutate of [
  p=>{p.explicitPortSourceAliases['source-port']='dstport';},
  p=>{p.advisoryNameOnlySources=p.advisoryNameOnlySources.filter(x=>x!=='srcport');},
]){
  const copy=structuredClone(policy);mutate(copy);
  assert.throws(()=>validateCanonicalPolicy(copy));
}
const forged=structuredClone(profiles);
forged.profiles.find(p=>p.id==='stellar70-observed-ruby24').regexDeadlineCapable=true;
assert.throws(()=>validateNativeProfiles(forged));
console.log('EXECUTABLE_CONTRACT_GATE_PASS: policy, consumers, oracle inventory, runtime truth and same-HEAD CI; targetIndexedProof=false');
