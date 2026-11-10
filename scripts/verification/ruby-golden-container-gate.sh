#!/usr/bin/env bash
# Mandatory CI gate: the Ruby Fragments the browser golden spec downloaded are
# executed on the pinned Ruby 2.4.9 target image (no network, no mounts, read-only
# root) and their events are compared with the publisher-documented values from
# the Golden Corpus. Synthetic input is never used here. This is not a Stellar
# Cyber import, Syslog reception or indexing result.
#
#   ruby-golden-container-gate.sh <downloads-dir>            # Ruby 2.4.9 container
#   ruby-golden-container-gate.sh <downloads-dir> --local    # host `ruby` (PARSER_RUBY_BIN), for local checks
set -euo pipefail
dir="${1:?usage: ruby-golden-container-gate.sh <downloads-dir> [--local]}"
mode="${2:-container}"
tsx=backend/node_modules/tsx/dist/cli.mjs
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
node "$tsx" scripts/verification/golden-ruby-gate.ts prepare "$dir" "$work/input.json"
runner=$(cat scripts/verification/ruby-golden-event-runner.rb)
if [ "$mode" = "--local" ]; then
  "${PARSER_RUBY_BIN:-ruby}" -e "$runner" < "$work/input.json" > "$work/output.json"
  node "$tsx" scripts/verification/golden-ruby-gate.ts compare "$dir" "$work/output.json"
  exit 0
fi
for binary in docker timeout node; do
  command -v "$binary" >/dev/null || { echo GOLDEN_RUBY_RUNTIME_MISSING >&2; exit 1; }
done
target_image=$(node -e 'const c=require("./contracts/target-runtime-profiles.v1.json");const p=c.profiles.find(x=>x.id==="stellar70-observed-ruby24");if(!p?.ciContainerImage?.startsWith("ruby:2.4.9@sha256:"))process.exit(1);process.stdout.write(p.ciContainerImage)')
docker pull --platform linux/amd64 "$target_image" >/dev/null
timeout --kill-after=5s 90s docker run --rm -i --platform linux/amd64 \
  --network none --ipc none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 32 --memory 512m --cpus 1 \
  --ulimit nofile=64:64 --ulimit cpu=60:60 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --user 65532:65532 \
  "$target_image" ruby -e "$runner" < "$work/input.json" > "$work/output.json"
node "$tsx" scripts/verification/golden-ruby-gate.ts compare "$dir" "$work/output.json" --expect-ruby 2.4.9
echo GOLDEN_RUBY_CONTAINER_GATE_PASS
