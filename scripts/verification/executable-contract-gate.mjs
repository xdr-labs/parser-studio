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
      f.profile===ruby24.id&&f.behavior==='FAIL_CLOSED_RUNTIME'&&
      f.shippingExportBehavior==='TARGET_RUNTIME_REGEX_UNSUPPORTED'),
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
assert.ok(existsSync('scripts/verification/executable-artifact-lineage.ts'));
assert.match(text('.github/workflows/quality.yml'),/parser-studio-artifact-lineage-native/);
assert.match(text('.github/workflows/quality.yml'),/parser-studio-artifact-lineage-web/);
// Ruby 2.4 Regex never escapes the shipping export boundary, even if the
// internal, synthetic Ruby3.2 compiler can still emit DRAFT parser fragments.
assert.ok(existsSync('backend/src/target-runtime-export.ts'));
assert.ok(existsSync('backend/test/r3-target-regex-export-gate.test.ts'));
assert.match(text('backend/src/mainline-authoring-server.ts'),/requiresUnavailableTargetRegex/);
assert.match(text('backend/src/mainline-authoring-server.ts'),/pairIncludesUnavailableTargetRegex/);
assert.match(text('backend/src/mainline-authoring-server.ts'),/TARGET_REGEX_EXPORT_ERROR/);
assert.match(text('backend/src/target-runtime-export.ts'),/regexExportSupported: false/);
assert.match(text('backend/src/target-runtime-export.ts'),/ruby: "2.4.9"/);
assert.match(text('backend/src/target-runtime-export.ts'),/fluentd: "1.7.4"/);
assert.match(text('src/guided/backendCapabilities.ts'),/TARGET_RUNTIME_REGEX_UNSUPPORTED/);
assert.match(text('backend/src/compiler.ts'),/Regexp\.respond_to\?\(:timeout=\)/);
assert.match(text('backend/src/compiler.ts'),/Native Regex unsupported/);
const workflow=text('.github/workflows/quality.yml');
assert.match(workflow,/H4_RELEASE_ELIGIBILITY_NOT_EVALUATED_ON_PR/);
assert.match(workflow,/GITHUB_EVENT_NAME.*pull_request/);
assert.match(workflow,/for label in P0 P1/);
assert.doesNotMatch(workflow,/ref: 03624952a8c097e5423df32b40ec64137f029f49/);
const exactPrHeadExpr="${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}";
assert.equal(workflow.split('ref: '+exactPrHeadExpr).length-1,4,
  'all 4 GitHub Actions checkouts must use exact PR source commit');
assert.match(workflow,/needs: \[native-isolated-synthetic, web-quality\]/);
assert.match(workflow,/actions\/download-artifact@v4/);
assert.match(workflow,/reconcile-artifact-lineage\.mjs/);
assert.ok(existsSync('scripts/verification/build-once-distribution.mjs'));
assert.ok(existsSync('scripts/verification/build-once-distribution.test.mjs'));
assert.equal(workflow.split('name: parser-studio-build-once-distribution').length-1,2,
  'one producer and one release-gate consumer must share the exact bundle');
assert.match(workflow,/node scripts\/verification\/build-once-distribution\.mjs create/);
assert.match(workflow,/node scripts\/verification\/build-once-distribution\.mjs verify/);
assert.ok(workflow.indexOf('Verify and package one exact-HEAD distribution after E2E')>
  workflow.indexOf('Same-HEAD authoring-only HTTP and beginner Chromium acceptance'),
  'the CI output must be published only after the complete user E2E');
assert.ok(workflow.indexOf('Independently validate exact-HEAD distributed runtime bytes')<
  workflow.indexOf('Reject any open P0 or P1 issue before merge'),
  'the main release gate must fail closed on divergent real deployment bytes');

assert.ok(workflow.includes('PARSER_STUDIO_BACKEND_HEAD: '+exactPrHeadExpr),
  'browser backend source must follow exact frontend PR head');
assert.equal(workflow.split('PARSER_STUDIO_EXPECTED_SOURCE_HEAD: '+exactPrHeadExpr).length-1,5,
  'all 5 source-validating and distribution-verifying steps must state the exact source SHA');
assert.doesNotMatch(workflow,/PARSER_STUDIO_BACKEND_HEAD: \$\{\{ github\.sha \$\}\}/);
assert.doesNotMatch(workflow,/r\.sourceHead!==process\.env\.GITHUB_SHA/,
  'lineage receipts must compare actual PR source SHA, not GitHub synthetic merge SHA');
assert.equal(
  workflow.split('r.sourceHead!==process.env.PARSER_STUDIO_EXPECTED_SOURCE_HEAD').length-1,
  2,'both Native and Web receipt verifiers must check the same PR source SHA');
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
