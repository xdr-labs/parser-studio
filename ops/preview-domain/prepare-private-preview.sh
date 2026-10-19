#!/usr/bin/env bash
# Unprivileged staging for an exact committed HEAD. Does not touch Nginx,
# systemd, credentials, production hosts, or real Stellar/DP devices.
set -euo pipefail
umask 022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"
[[ -z "$(git status --porcelain --untracked-files=no)" ]] ||
  { echo 'Tracked working tree is dirty; commit and requalify before packaging.' >&2; exit 1; }
HEAD=$(git rev-parse HEAD)
[[ "$HEAD" =~ ^[0-9a-f]{40}$ ]] ||
  { echo 'Unexpected Git HEAD.' >&2; exit 1; }
[[ ! -e "$ROOT/dist/private-preview" ]] ||
  { echo 'An existing preview package must be preserved; do not rebuild over it.' >&2; exit 1; }
[[ -L node_modules && -L backend/node_modules ]] ||
  { echo 'Qualified local build dependencies must be installed first.' >&2; exit 1; }

echo "Building Parser Studio web + offline backend from exact HEAD $HEAD"
npm run build
npm --prefix backend run build
[[ -f dist/index.html && -f backend/dist/src/mainline-authoring-server.js ]] ||
  { echo 'Build output is incomplete.' >&2; exit 1; }

PACKAGE="$ROOT/dist/private-preview"
[[ ! -e "$PACKAGE" ]] ||
  { echo 'Preview package exists; do not overwrite it implicitly.' >&2; exit 1; }
STAGE=$(mktemp -d "$ROOT/dist/.private-preview-stage-XXXXXX")
cleanup(){ [[ -d "$STAGE" ]] && rm -rf -- "$STAGE"; }
trap cleanup EXIT
mkdir -p "$STAGE/web" "$STAGE/backend/dist" "$STAGE/multipass"
# Only normal production files; do not stage private fixtures or test secrets.
cp -a dist/assets dist/index.html "$STAGE/web/"
cp -a backend/dist/. "$STAGE/backend/dist/"
cp backend/package.json backend/package-lock.json "$STAGE/backend/"
cp runtime/multipass/*.py "$STAGE/multipass/"
(
  cd "$STAGE/backend"
  npm ci --omit=dev --ignore-scripts --no-audit --no-fund
)
# .bin symlinks are command wrappers, never required by the compiled API.
rm -rf -- "$STAGE/backend/node_modules/.bin"
if find "$STAGE" -type l -print -quit | grep -q .; then
  echo 'Deployment contains symlinks; aborting.' >&2
  exit 1
fi
printf '%s\n' "$HEAD" > "$STAGE/COMMIT"
printf '%s\n' "$HEAD" > "$ROOT/dist/.parser-studio-built-head"
(
  cd "$STAGE"
  find web backend multipass -type f -print0 | sort -z | xargs -0 sha256sum > FILES.sha256
  sha256sum -c FILES.sha256 >/dev/null
)
mv -- "$STAGE" "$PACKAGE"
trap - EXIT
printf 'Offline preview package ready: %s\nExact HEAD: %s\n' "$PACKAGE" "$HEAD"
printf 'No privileged Nginx, systemd, TLS, authentication or network change performed.\n'
