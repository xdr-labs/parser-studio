#!/usr/bin/env bash
# H2: exact-HEAD generated Ruby / Fluentd, fixed synthetic evidence ONLY.
# Runtime has no network, writable root, elevated caps, host mounts or secrets.
set -euo pipefail
if [[ -n "${PARSER_STUDIO_NATIVE_USER_INPUT:-}" ]]; then
  echo 'H2_FIXED_SYNTHETIC_ONLY' >&2
  exit 1
fi
for command in docker timeout node; do
  command -v "$command" >/dev/null || { echo 'H2_ISOLATION_RUNTIME_UNAVAILABLE' >&2; exit 1; }
done
docker info >/dev/null
private_input=$(mktemp)
private_receipt=$(mktemp)
chmod 600 "$private_input" "$private_receipt"
trap 'rm -f "$private_input" "$private_receipt"' EXIT

# Build is allowed to retrieve locked gems. Execution explicitly is NOT.
docker build --pull --file backend/native_isolation/Dockerfile \
  --tag parserstudio-h2-ci-native:local .
image_id=$(docker image inspect parserstudio-h2-ci-native:local --format '{{.Id}}')
[[ "$image_id" == sha256:* ]] || { echo 'H2_IMAGE_ID_UNVERIFIED' >&2; exit 1; }

# No mounts, no Docker socket, no published ports, no ambient env inheritance.
# Only stdin contains PRIVATE fixed-synthetic inputs; stdout holds sanitized
# hash/count receipts. The fixed Ruby runner itself is baked into the image.
sandbox=(
  --rm -i
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 64
  --memory 512m
  --cpus 1
  --ulimit nofile=64:64
  --tmpfs /tmp:rw,noexec,nosuid,size=16m
  --user 65532:65532
)

# Explicitly verify isolation at runtime, rather than relying on a manifest.
# A false network or read-only claim causes the CI job to fail.
timeout --kill-after=5s 20s docker run "${sandbox[@]}" \
  --entrypoint ruby parserstudio-h2-ci-native:local \
  -rsocket -e '
    abort "H2_ROOT_EXECUTION" if Process.uid == 0
    begin
      File.write("/etc/parserstudio-h2-unexpected-write", "x")
      abort "H2_WRITABLE_ROOT"
    rescue Errno::EROFS, Errno::EACCES
    end
    begin
      Socket.tcp("1.1.1.1", 53, connect_timeout: 1) { |_| }
      abort "H2_OUTBOUND_NETWORK"
    rescue SystemCallError, SocketError
    end
    puts "H2_OFFLINE_NONROOT_READONLY_PASS"
  '

node backend/node_modules/tsx/dist/cli.mjs \
  scripts/verification/h2-isolated-native-input.ts >"$private_input"
test "$(wc -c < "$private_input")" -gt 1
timeout --kill-after=5s 45s docker run "${sandbox[@]}" \
  parserstudio-h2-ci-native:local <"$private_input" >"$private_receipt"

node backend/node_modules/tsx/dist/cli.mjs \
  scripts/verification/h2-isolated-native-verify.ts "$private_receipt"
echo "H2_CONTAINER_IMAGE_ID=$image_id"
