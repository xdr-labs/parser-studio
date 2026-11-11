#!/usr/bin/env bash
# Real UDP 6801 reception on Ruby 2.4.9 + Fluentd 1.7.4 with the generated .conf.
# Execution is sealed (no network, read-only root, no mounts). Only the image
# build may reach the gem registry. Fixed Cisco-published inputs only.
set -euo pipefail
for command in docker timeout node; do
  command -v "$command" >/dev/null || { echo 'UDP_GATE_RUNTIME_UNAVAILABLE' >&2; exit 1; }
done
target_image=$(node -e 'const c=require("./contracts/target-runtime-profiles.v1.json");const p=c.profiles.find(x=>x.id==="stellar70-observed-ruby24");if(!p?.ciContainerImage?.startsWith("ruby:2.4.9@sha256:"))process.exit(1);process.stdout.write(p.ciContainerImage)')
docker pull --platform linux/amd64 "$target_image" >/dev/null
docker build --platform linux/amd64 --build-arg BASE_IMAGE="$target_image" \
  --file backend/native_isolation/Dockerfile.ruby24-fluentd \
  --tag parserstudio-ruby24-fluentd:ci .
payload=$(mktemp)
chmod 600 "$payload"
trap 'rm -f "$payload"' EXIT
node backend/node_modules/tsx/dist/cli.mjs \
  scripts/verification/ruby24-fluentd-udp-evidence.ts --private-payload > "$payload"
test "$(wc -c < "$payload")" -gt 1000
test "$(wc -c < "$payload")" -lt 262144
runner=$(cat scripts/verification/ruby24-fluentd-udp-runner.rb)
timeout --kill-after=5s 90s docker run --rm -i --platform linux/amd64 \
  --network none --ipc none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 512m --cpus 1 \
  --ulimit nofile=1024:1024 --ulimit cpu=60:60 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  --user 65532:65532 \
  parserstudio-ruby24-fluentd:ci ruby -e "$runner" < "$payload"
echo RUBY24_FLUENTD_UDP_GATE_DONE
