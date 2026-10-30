#!/bin/bash
# Development Preview, web-only release helper (see UPDATE_RUNBOOK.md section 11). Run as root on dev-atlas.
#   release_web.sh <full-40-char-sha> build   : worktree + npm ci + npm run build + generated deploy_web.sh (live app untouched)
#   release_web.sh <full-40-char-sha> apply   : run the generated deploy_web.sh apply (fail-closed, rolls itself back)
# Rollback afterwards: $REL/deploy_web.sh rollback. Use it only when backend and Multi-Pass comparisons are empty;
# a backend change needs the full procedure in the runbook.
set -uo pipefail
SHA=${1:?full 40-char commit sha}; STEP=${2:-build}
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "need the full 40-character sha"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "need root"; exit 2; }
ST=${PS_ROLLOUTS:-/home/aella/.local/state/parserstudio-public-rollouts}
CORE=${PS_CORE:-/home/aella/.dev/parserstudio-core}
WEB=/var/www/parser-studio-app
HERE=$(cd "$(dirname "$0")" && pwd)
REL=$ST/release-${SHA:0:7}-$(date -u +%Y%m%d)
if [ "$STEP" = build ]; then
  mkdir -p "$REL" && chown aella:aella "$REL"
  exec >"$REL/build.out" 2>&1
  runuser -u aella -- git -C "$CORE" fetch origin main
  [ -e "$REL/src" ] || runuser -u aella -- git -C "$CORE" worktree add --detach "$REL/src" "$SHA" || { echo BUILD_FAIL worktree; exit 1; }
  [ "$(runuser -u aella -- git -c safe.directory='*' -C "$REL/src" rev-parse HEAD)" = "$SHA" ] || { echo BUILD_FAIL head; exit 1; }
  echo "$SHA" > "$REL/commit.txt"
  OLD=$(sha256sum "$WEB/index.html" | cut -c1-64)
  { echo "utc $(date -u +%FT%TZ)"; echo "live index: $OLD";
    echo "public index: $(curl -fsS -H 'Cache-Control: no-cache' https://app.parser.xdr.ooo/ | sha256sum | cut -c1-64)";
    echo "authoring pid=$(systemctl show parser-studio-preview-authoring.service -p MainPID --value) multipass pid=$(systemctl show parser-studio-preview-multipass.service -p MainPID --value)"; } > "$REL/baseline-before.txt"
  (cd "$REL/src" && runuser -u aella -- npm ci --no-audit --no-fund > "$REL/npm_ci_web.log" 2>&1 \
    && runuser -u aella -- npm run build > "$REL/build_web.log" 2>&1) || { echo BUILD_FAIL npm; exit 1; }
  sed -e "s#@REL@#$REL#" -e "s#@HEADSHA@#$SHA#" -e "s#@OLD_INDEX@#$OLD#" "$HERE/deploy_web.sh.tpl" > "$REL/deploy_web.sh"
  chmod 755 "$REL/deploy_web.sh"
  echo BUILD_OK
elif [ "$STEP" = apply ]; then
  "$REL/deploy_web.sh" apply 2>&1 | tee -a "$REL/apply.out"
else
  echo "usage: $0 <sha> build|apply"; exit 2
fi
