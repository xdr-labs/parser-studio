#!/usr/bin/env bash
# Mandatory CI gate: EVERY enumerated compiler variant (backend/test/
# compiler-variants.ts) is compiled with the real compilePair and its generated
# Ruby Fragment is checked offline on the pinned Ruby 2.4.9 target image and on
# the Ruby 3.2.11 CI image: syntax, Ripper top-level shape, wrapper-surface
# embedding and empty/non-log input behavior. The containers have no network,
# mounts or writeable root. Synthetic fixtures only; this is not a Stellar Cyber
# import, Syslog reception or indexing result.
#
# Optional arguments (used by the downloaded-artifact gate):
#   --payload FILE   check this prepared payload instead of the compiler variants
#   --profiles LIST  comma separated subset of ruby24,ruby32 (default both)
set -euo pipefail
payload_file=""
profiles="ruby24,ruby32"
while [ $# -gt 0 ]; do
  case "$1" in
    --payload) payload_file="$2"; shift 2 ;;
    --profiles) profiles="$2"; shift 2 ;;
    *) echo RUBY_VARIANT_MATRIX_BAD_ARGUMENT >&2; exit 1 ;;
  esac
done
case ",$profiles," in *,ruby24,*|*,ruby32,*) ;; *) echo RUBY_VARIANT_MATRIX_BAD_PROFILES >&2; exit 1 ;; esac
for binary in docker timeout node; do
  command -v "$binary" >/dev/null || { echo RUBY_VARIANT_MATRIX_RUNTIME_MISSING >&2; exit 1; }
done
target_image=$(node -e 'const c=require("./contracts/target-runtime-profiles.v1.json");const p=c.profiles.find(x=>x.id==="stellar70-observed-ruby24");if(!p?.ciContainerImage?.startsWith("ruby:2.4.9@sha256:"))process.exit(1);process.stdout.write(p.ciContainerImage)')
ruby32_image='parserstudio-h2-ci-native:local'
case ",$profiles," in *,ruby32,*) docker image inspect "$ruby32_image" >/dev/null ;; esac
docker pull --platform linux/amd64 "$target_image" >/dev/null
if [ -n "$payload_file" ]; then
  payload="$payload_file"
else
  payload=$(mktemp)
  chmod 600 "$payload"
  trap 'rm -f "$payload"' EXIT
  node backend/node_modules/tsx/dist/cli.mjs \
    scripts/verification/ruby-variant-matrix-payload.ts --private-payload > "$payload"
fi
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
case ",$profiles," in *,ruby24,*)
  timeout --kill-after=5s 90s docker run "${sandbox[@]}" \
    "$target_image" ruby -e "$runner" -- ruby24 < "$payload" ;;
esac
case ",$profiles," in *,ruby32,*)
  timeout --kill-after=5s 90s docker run "${sandbox[@]}" \
    --entrypoint ruby "$ruby32_image" -e "$runner" -- ruby32 < "$payload" ;;
esac
echo RUBY_VARIANT_MATRIX_GATE_PASS
