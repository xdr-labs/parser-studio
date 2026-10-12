#!/usr/bin/env bash
# Bounded offline verification of generated synthetic fixtures only.
# No Stellar Cyber operations, no live td-agent, no TCP/UDP listeners.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[1/5] Node/TypeScript schema, compiler and local HTTP tests"
npm run check
npm test
npm run build
node dist/scripts/create-synthetic.js

echo "[1b/5] Synthetic import round-trip + no-echo tamper gate"
node dist/scripts/inspect-synthetic.js

RUBY_COMMAND="${PARSER_RUBY_BIN:-ruby}"
if ! command -v "$RUBY_COMMAND" >/dev/null 2>&1; then
  LOCAL_ROOT="$ROOT/.tmp/ruby-root"
  if [[ -x "$LOCAL_ROOT/usr/bin/ruby3.2" ]]; then
    RUBY_COMMAND="$LOCAL_ROOT/usr/bin/ruby3.2"
    export LD_LIBRARY_PATH="$LOCAL_ROOT/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export RUBYLIB="$LOCAL_ROOT/usr/lib/ruby/3.2.0:$LOCAL_ROOT/usr/lib/x86_64-linux-gnu/ruby/3.2.0${RUBYLIB:+:$RUBYLIB}"
    export GEM_HOME="${GEM_HOME:-$ROOT/.tmp/gems}"
    export GEM_PATH="${GEM_PATH:-$ROOT/.tmp/gems}"
  else
    echo "ERROR: Ruby 3.2 unavailable; set PARSER_RUBY_BIN or install in an isolated runner." >&2
    exit 1
  fi
fi

# Apply identical non-privileged resource limits to every isolated Ruby child.
# This is a bounded offline smoke harness, not a sandbox for untrusted uploads.
RUBY_MAX_VIRTUAL_KIB=1048576
RUBY_MAX_CPU_SECONDS=30
RUBY_MAX_WALL_SECONDS=25
run_bounded_ruby() {
  (
    ulimit -v "$RUBY_MAX_VIRTUAL_KIB" || exit 1
    ulimit -t "$RUBY_MAX_CPU_SECONDS" || exit 1
    timeout --signal=TERM --kill-after=2s "$RUBY_MAX_WALL_SECONDS"s "$RUBY_COMMAND" "$@"
  )
}

echo "[2a/5] Assert Ruby child process resource budget"
run_bounded_ruby --disable-gems test_native/runner_limits_smoke.rb

echo "[2/5] Locked Ruby/Fluentd profile"
run_bounded_ruby -v
run_bounded_ruby -rbundler/setup -e '
  raise "Fluentd version mismatch" unless Gem.loaded_specs.fetch("fluentd").version.to_s == "1.17.1"
  puts "fluentd=1.17.1 test-unit=#{Gem::Specification.find_by_name("test-unit").version}"
'

echo "[2b/5] Verify generated Ruby/CONF integrity before any native execution"
run_bounded_ruby --disable-gems test_native/synthetic_integrity_smoke.rb

echo "[3/5] Ruby parser syntax and pure callback fixtures"
for file in .tmp/native-fixtures/customized_*; do
  [[ "$file" == *.conf ]] && continue
  run_bounded_ruby --disable-gems -c "$file"
done
run_bounded_ruby --disable-gems test_native/fragment_smoke.rb .tmp/native-fixtures
run_bounded_ruby --disable-gems test_native/format_smoke.rb .tmp/native-fixtures
run_bounded_ruby --disable-gems test_native/rfc5424_sd_smoke.rb
run_bounded_ruby --disable-gems test_native/enrichment_smoke.rb .tmp/native-fixtures

echo "[4/5] Fluentd native parser API and configuration grammar"
# No uploaded Ruby is evaluated. A fixed template and synthetics are tested.
run_bounded_ruby -rbundler/setup test_native/fluentd_plugin_smoke.rb .tmp/native-fixtures
run_bounded_ruby -rbundler/setup test_native/fluentd_config_smoke.rb .tmp/native-fixtures
echo "[4b/5] Immutable synthetic golden expected-record comparison via pinned Fluentd API"
run_bounded_ruby -rbundler/setup test_native/golden_events_smoke.rb \
  .tmp/native-fixtures test_native/fixtures/synthetic-golden.v0.1.json
# Attempting to substitute an arbitrary Ruby source path must fail before class_eval.
if guard_output=$(run_bounded_ruby -rbundler/setup \
    test_native/golden_events_smoke.rb /tmp/native-untrusted \
    test_native/fixtures/synthetic-golden.v0.1.json 2>&1); then
  echo "ERROR: Golden runner accepted an untrusted source directory." >&2
  exit 1
elif [[ "$guard_output" != *"Synthetic native fixture boundary"* ]]; then
  echo "ERROR: Golden runner did not fail by its explicit fixture boundary." >&2
  exit 1
fi
echo "Golden runner untrusted-path refusal PASS"

echo "[4c/5] Strict offline POC disposable null-sink CONF grammar with Fluentd AST"
node dist/scripts/stellar-disposable-smoke.js |
  run_bounded_ruby -rbundler/setup test_native/stellar_poc_disposable_config_smoke.rb

echo "[5/5] Immutable-style synthetic evidence manifest"
node --input-type=module <<'NODE'
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
const files = readdirSync(".tmp/native-fixtures").filter(x => x.startsWith("customized_")).sort();
const hashes = Object.fromEntries(files.map(name =>
  [name, createHash("sha256").update(readFileSync(".tmp/native-fixtures/"+name)).digest("hex")]
));
const head = execFileSync("git",["rev-parse","HEAD"],{encoding:"utf8"}).trim();
const imported = JSON.parse(readFileSync(".tmp/synthetic-import-report.json","utf8"));
if (imported.backendHead !== head || imported.origin !== "synthetic-repository-fixtures" ||
    imported.verifiedExactPairs !== files.length/2 ||
    imported.rejectedModifiedPairs !== files.length/2 ||
    imported.targetImportVerified !== false ||
    Object.keys(imported.originalHashes).length !== files.length ||
    files.some(name => hashes[name] !== imported.originalHashes[name])) {
  throw new Error("Synthetic pair import evidence does not match generated native fixture hashes");
}
const golden = JSON.parse(readFileSync(".tmp/synthetic-golden-report.json","utf8"));
const fixtureBytes = readFileSync("test_native/fixtures/synthetic-golden.v0.1.json");
const fixtureSha256 = createHash("sha256").update(fixtureBytes).digest("hex");
if (golden.backendHead !== head || golden.origin !== "independently-authored-public-synthetic" ||
    golden.kind !== "parser-studio.synthetic-golden-native.v0.1" ||
    golden.fixtureSha256 !== fixtureSha256 || golden.casesPassed !== 23 ||
    golden.profilesPassed !== 10 || golden.fluentd !== "1.17.1" ||
    golden.actualTdAgentOrStellarImport !== false ||
    golden.targetImportVerified !== false) {
  throw new Error("Pinned Fluentd synthetic golden evidence is missing or mismatched");
}
const dirty = execFileSync("git",["status","--porcelain"],{encoding:"utf8"}).trim().length > 0;
const report = {
  kind: "xdr-labs.parser-studio.synthetic-native-profile.v0.1",
  backendHead: head, worktreeDirty: dirty,
  origin: "synthetic-repository-fixtures",
  rubyProfile: "3.2", fluentd: "1.17.1", fixturePairs: files.length / 2,
  result: "SYNTHETIC_FLUENTD_PARSER_AND_CONF_AST_PASS",
  pluginParserCallbackChecked: true,
  generatedFixtureSourceIntegrityChecked: true,
  rubyChildVirtualMemoryLimitKiB: 1048576,
  rubyChildCpuLimitSeconds: 30,
  rubyChildWallLimitSeconds: 25,
  rubyChildResourceLimitsChecked: true,
  pocDisposableLoopbackNullSinkAstChecked: true,
  pocApiMutationPerformed: false,
  rfc5424SdNameAndParameterGrammarChecked: true,
  rfc5424SdPositiveCases: 2,
  rfc5424SdNegativeCases: 9,
  sourceIntegrityNegativeCases: 4,
  configParsedWithTransportIncludeRemovedInMemory: true,
  verifiedExactPairImports: imported.verifiedExactPairs,
  rejectedModifiedPairImports: imported.rejectedModifiedPairs,
  syntheticGoldenCases: golden.casesPassed,
  syntheticGoldenProfiles: golden.profilesPassed,
  syntheticGoldenFixtureHash: golden.fixtureSha256,
  actualTdAgentOrStellarImport: false,
  targetImportVerified: false,
  fileHashes: hashes,
  caveat: "Not an installed plugin/wrapper test; not a live listener or Stellar target import."
};
writeFileSync(".tmp/synthetic-native-report.json",JSON.stringify(report,null,2)+"\n",{mode:0o600});
console.log("SHA-256 hashes: "+files.length+"; HEAD="+head.slice(0,12)+"; dirty="+dirty);
NODE
echo "PASS synthetic native parser profile, NOT Stellar Cyber deployment."
