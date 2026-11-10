#!/usr/bin/env bash
# Mandatory CI gate: EVERY enumerated compiler variant (backend/test/
# compiler-variants.ts) is compiled with the real compilePair and its generated
# Ruby Fragment is checked offline on the pinned Ruby 2.4.9 target image and on
# the Ruby 3.2.11 CI image: syntax, Ripper top-level shape, wrapper-surface
# embedding and empty/non-log input behavior. The containers have no network,
# mounts or writeable root. Synthetic fixtures only; this is not a Stellar Cyber
# import, Syslog reception or indexing result.
set -euo pipefail
for binary in docker timeout node; do
  command -v "$binary" >/dev/null || { echo RUBY_VARIANT_MATRIX_RUNTIME_MISSING >&2; exit 1; }
done
target_image=$(node -e 'const c=require("./contracts/target-runtime-profiles.v1.json");const p=c.profiles.find(x=>x.id==="stellar70-observed-ruby24");if(!p?.ciContainerImage?.startsWith("ruby:2.4.9@sha256:"))process.exit(1);process.stdout.write(p.ciContainerImage)')
ruby32_image='parserstudio-h2-ci-native:local'
docker image inspect "$ruby32_image" >/dev/null
docker pull --platform linux/amd64 "$target_image" >/dev/null
payload=$(mktemp)
chmod 600 "$payload"
trap 'rm -f "$payload"' EXIT
node backend/node_modules/tsx/dist/cli.mjs \
  scripts/verification/ruby-variant-matrix-payload.ts --private-payload > "$payload"
test "$(wc -c < "$payload")" -gt 1000
test "$(wc -c < "$payload")" -lt 16777216
runner=$(cat scripts/verification/ruby-variant-matrix-runner.rb)
sandbox=(
  --rm -i --platform linux/amd64
  --network none --ipc none --read-only
  --cap-drop ALL --security-opt no-new-privileges
  --pids-limit 32 --memory 512m --cpus 1
  --ulimit nofile=64:64 --ulimit cpu=60:60
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m
  --user 65532:65532
)
timeout --kill-after=5s 90s docker run "${sandbox[@]}" \
  "$target_image" ruby -e "$runner" -- ruby24 < "$payload"
timeout --kill-after=5s 90s docker run "${sandbox[@]}" \
  --entrypoint ruby "$ruby32_image" -e "$runner" -- ruby32 < "$payload"
echo RUBY_VARIANT_MATRIX_GATE_PASS
