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

echo "[2/5] Locked Ruby/Fluentd profile"
"$RUBY_COMMAND" -v
"$RUBY_COMMAND" -rbundler/setup -e '
  raise "Fluentd version mismatch" unless Gem.loaded_specs.fetch("fluentd").version.to_s == "1.17.1"
  puts "fluentd=1.17.1 test-unit=#{Gem::Specification.find_by_name("test-unit").version}"
'

echo "[3/5] Ruby parser syntax and pure callback fixtures"
for file in .tmp/native-fixtures/customized_*; do
  [[ "$file" == *.conf ]] && continue
  "$RUBY_COMMAND" --disable-gems -c "$file"
done
"$RUBY_COMMAND" --disable-gems test_native/fragment_smoke.rb .tmp/native-fixtures
"$RUBY_COMMAND" --disable-gems test_native/format_smoke.rb .tmp/native-fixtures
"$RUBY_COMMAND" --disable-gems test_native/enrichment_smoke.rb .tmp/native-fixtures

echo "[4/5] Fluentd native parser API and configuration grammar"
# No uploaded Ruby is evaluated. A fixed template and synthetics are tested.
timeout 25s "$RUBY_COMMAND" -rbundler/setup test_native/fluentd_plugin_smoke.rb .tmp/native-fixtures
timeout 25s "$RUBY_COMMAND" -rbundler/setup test_native/fluentd_config_smoke.rb .tmp/native-fixtures

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
const dirty = execFileSync("git",["status","--porcelain"],{encoding:"utf8"}).trim().length > 0;
const report = {
  kind: "xdr-labs.parser-studio.synthetic-native-profile.v0.1",
  backendHead: head, worktreeDirty: dirty,
  origin: "synthetic-repository-fixtures",
  rubyProfile: "3.2", fluentd: "1.17.1", fixturePairs: files.length / 2,
  result: "SYNTHETIC_FLUENTD_PARSER_AND_CONF_AST_PASS",
  pluginParserCallbackChecked: true,
  configParsedWithTransportIncludeRemovedInMemory: true,
  actualTdAgentOrStellarImport: false,
  targetImportVerified: false,
  fileHashes: hashes,
  caveat: "Not an installed plugin/wrapper test; not a live listener or Stellar target import."
};
writeFileSync(".tmp/synthetic-native-report.json",JSON.stringify(report,null,2)+"\n",{mode:0o600});
console.log("SHA-256 hashes: "+files.length+"; HEAD="+head.slice(0,12)+"; dirty="+dirty);
NODE
echo "PASS synthetic native parser profile, NOT Stellar Cyber deployment."
