#!/usr/bin/env bash
# Mandatory CI-on-target-Ruby-version semantic parity for a fixed synthetic
# generated fragment. The container has no network, mounts or writeable root.
set -euo pipefail
for binary in docker timeout node; do
  command -v "$binary" >/dev/null || { echo NATIVE_REGEX_CI_RUNTIME_MISSING >&2; exit 1; }
done
# Official Docker Ruby tag 2.4.9, exact amd64 manifest digest (verified from
# Docker Hub official library tag metadata). Not a supported deployment image.
target_image=$(node -e 'const c=require("./contracts/target-runtime-profiles.v1.json");const p=c.profiles.find(x=>x.id==="stellar70-observed-ruby24");if(!p?.ciContainerImage?.startsWith("ruby:2.4.9@sha256:"))process.exit(1);process.stdout.write(p.ciContainerImage)')
ruby32_image='parserstudio-h2-ci-native:local'
docker image inspect "$ruby32_image" >/dev/null
docker pull --platform linux/amd64 "$target_image" >/dev/null
payload=$(mktemp)
chmod 600 "$payload"
trap 'rm -f "$payload"' EXIT
node backend/node_modules/tsx/dist/cli.mjs \
  scripts/verification/ruby24-regex-artifact-evidence.ts --private-payload > "$payload"
test "$(wc -c < "$payload")" -gt 1000
# Six fixed fixtures of ~45 KB each (shared template, compressed). The cap only bounds
# the stdin payload; it was raised from 256 KiB when the Cisco ASA fixture was added.
test "$(wc -c < "$payload")" -lt 393216
runner=$(cat scripts/verification/ruby24-regex-offline-runner.rb)
sandbox=(
  --rm -i --platform linux/amd64
  --network none --ipc none --read-only
  --cap-drop ALL --security-opt no-new-privileges
  --pids-limit 32 --memory 256m --cpus 1
  --ulimit nofile=64:64 --ulimit cpu=15:15
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m
  --user 65532:65532
)
timeout --kill-after=5s 20s docker run "${sandbox[@]}" \
  "$target_image" ruby -e "$runner" -- ruby24 < "$payload"
timeout --kill-after=5s 20s docker run "${sandbox[@]}" \
  --entrypoint ruby "$ruby32_image" -e "$runner" -- ruby32 < "$payload"
echo TARGET_RUBY_VERSION_GUARD_PASS
