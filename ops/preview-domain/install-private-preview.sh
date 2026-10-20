#!/usr/bin/env bash
# Owner-executed privileged change. Never run this from the assistant's
# unprivileged development session or skip the explicit operator approval.
set -euo pipefail
umask 077

SITE=app.parser.xdr.ooo
ROOT=/home/aella/parser-studio-secure-domain-20261019
STAGED=/etc/nginx/sites-available/$SITE
ENABLED=/etc/nginx/sites-enabled/$SITE
SVC=parser-studio-preview-multipass.service
BACKEND_SVC=parser-studio-preview-authoring.service
PKG="$ROOT/dist/private-preview"
WWW=/var/www/parser-studio-app
BACKEND=/opt/parser-studio-preview/backend
MULTIPASS=/opt/parser-studio-preview/multipass
ACME=/var/www/parser-studio-acme

die(){ printf 'FAILED: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die 'Run as root using an already authorized administrator session.'
[[ "$#" == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || die 'Pass the verified exact Git HEAD as the only argument.'
[[ ! -e "$STAGED" && ! -e "$ENABLED" ]] || die 'Domain virtual host already exists; do not overwrite it.'
[[ ! -e "/etc/systemd/system/$SVC" && ! -e "/etc/systemd/system/$BACKEND_SVC" ]] ||
  die 'Preview service already exists; review before changing it.'
[[ -f "$PKG/web/index.html" && -f "$PKG/backend/dist/src/mainline-authoring-server.js" ]] ||
  die 'Exact-HEAD deployable web/backend package missing; run prepare-private-preview.sh first.'
[[ -f "$PKG/COMMIT" && "$(cat "$PKG/COMMIT")" == "$1" ]] ||
  die 'Offline preview package does not match the requested Git SHA.'
[[ -f "$ROOT/dist/.parser-studio-built-head" ]] || die 'The verified build HEAD marker is missing.'
[[ "$(cat "$ROOT/dist/.parser-studio-built-head")" == "$1" ]] || die 'Frontend build HEAD does not match the requested Git SHA.'
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$1" ]] || die 'Current source HEAD changed.'
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]] || die 'Tracked source is dirty; requalify it first.'
[[ -f "$ROOT/ops/preview-domain/nginx-app.parser.xdr.ooo.conf" ]] || die 'Audited Nginx configuration missing.'
[[ -f "$ROOT/ops/preview-domain/parser-studio-preview-multipass.service" ]] || die 'Multi-Pass unit missing.'
[[ -f "$ROOT/ops/preview-domain/parser-studio-preview-authoring.service" ]] || die 'Authoring API unit missing.'
[[ -f "$ROOT/ops/preview-domain/check-staged-files.sh" ]] || die 'Read-only staging verification is missing.'
[[ -f "$PKG/multipass/multipass_preview_api.py" ]] || die 'Source engine missing.'
( cd "$PKG" && sha256sum --status -c FILES.sha256 ) ||
  die 'Offline preview package failed integrity verification.'
if find "$PKG" -type l -print -quit | grep -q .; then
  die 'Deployment package contains symlinks; copy refused.'
fi
for bin in nginx certbot curl systemctl git openssl diff; do
  command -v "$bin" >/dev/null || die "Required command missing: $bin"
done
stage_mode=$(bash "$ROOT/ops/preview-domain/check-staged-files.sh" "$PKG" "$WWW" "$BACKEND" "$MULTIPASS") ||
  die 'An existing deployment does not exactly match the signed-off build. Nothing will be overwritten.'
[[ "$stage_mode" == FRESH || "$stage_mode" == REUSE_VERIFIED ]] ||
  die 'Unexpected staging inspection result.'
getent hosts "$SITE" | grep -q 221.139.249.116 || die 'DNS does not resolve to this authorized development server.'
if ss -ltn | grep -Eq '127\.0\.0\.1:(4304|4305)[[:space:]]'; then
  die 'Private preview port 4304 or 4305 is already occupied.'
fi

printf '\nThis installs a NEW no-login HTTPS Nginx virtual host for %s.\n' "$SITE"
printf 'It configures existing verified files, loopback services and an isolated Nginx site.\n'
printf 'The existing exporter.xdr.ooo configuration is preserved.\n'
printf 'Staged source files: %s\n' "$stage_mode"
certificate=/etc/letsencrypt/live/$SITE/fullchain.pem
private_key=/etc/letsencrypt/live/$SITE/privkey.pem
if [[ -f "$certificate" && -f "$private_key" ]] &&
   openssl x509 -checkend 86400 -noout -in "$certificate" >/dev/null; then
  echo 'Reusing the already-issued valid HTTPS certificate.'
  reuse_certificate=true
else
  reuse_certificate=false
  read -r -p "Let's Encrypt certificate contact email: " email
  [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] ||
    die 'Invalid certificate contact email.'
fi

# In a failure, restore the old Nginx set of enabled sites. Never touch the
# existing Exporter virtual host; certbot files can remain for manual review.
completed=0
cleanup(){
  rc=$?
  if (( completed == 0 )); then
    printf 'Preview setup did not complete; restoring previous Nginx host routing.\n' >&2
    rm -f "$ENABLED" "$STAGED"
    systemctl disable --now "$SVC" "$BACKEND_SVC" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$SVC" "/etc/systemd/system/$BACKEND_SVC"
    systemctl daemon-reload || true
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  fi
  exit "$rc"
}
trap cleanup EXIT

install -d -m 0755 "$ACME/.well-known/acme-challenge"
cat > "$STAGED" <<'NGINX_BOOTSTRAP'
server {
    listen 80;
    listen [::]:80;
    server_name app.parser.xdr.ooo;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/parser-studio-acme;
        default_type text/plain;
        try_files $uri =404;
    }
    location / { return 404; }
}
NGINX_BOOTSTRAP
ln -s "$STAGED" "$ENABLED"
nginx -t
systemctl reload nginx

if [[ "$reuse_certificate" != true ]]; then
  certbot certonly --webroot --webroot-path "$ACME" -d "$SITE" \
    --agree-tos --non-interactive --email "$email" --keep-until-expiring
fi

if [[ "$stage_mode" == FRESH ]]; then
  install -d -m 0755 "$WWW" "$BACKEND" "$MULTIPASS"
  cp -a "$PKG/web/." "$WWW/"
  cp -a "$PKG/backend/." "$BACKEND/"
  cp -a "$PKG/multipass/." "$MULTIPASS/"
  chmod -R a+rX "$WWW" "$BACKEND" "$MULTIPASS"
else
  echo 'Existing exact-byte-matched static, backend and parser files retained without overwrite.'
fi

install -m 0644 "$ROOT/ops/preview-domain/parser-studio-preview-multipass.service" "/etc/systemd/system/$SVC"
install -m 0644 "$ROOT/ops/preview-domain/parser-studio-preview-authoring.service" "/etc/systemd/system/$BACKEND_SVC"
systemctl daemon-reload
systemctl enable --now "$SVC" "$BACKEND_SVC"
wait_for_service() {
  local unit="$1" endpoint="$2" attempt
  # First Python import on a cold host can take longer than systemctl start.
  # Only report failure after bounded probes or a verified unit failure.
  for attempt in {1..40}; do
    if curl -fs --max-time 2 "$endpoint" >/dev/null; then
      printf '%s ready after probe %s.\n' "$unit" "$attempt"
      return 0
    fi
    if ! systemctl is-active --quiet "$unit"; then
      systemctl status "$unit" --no-pager -l >&2 || true
      journalctl -u "$unit" -n 25 --no-pager >&2 || true
      return 1
    fi
    sleep 1
  done
  systemctl status "$unit" --no-pager -l >&2 || true
  journalctl -u "$unit" -n 25 --no-pager >&2 || true
  return 1
}
wait_for_service "$SVC" http://127.0.0.1:4304/health ||
  die 'Isolated parser worker did not become ready within the bounded startup window.'
wait_for_service "$BACKEND_SVC" http://127.0.0.1:4305/api/v1/parser-pairs/capabilities ||
  die 'Exact-HEAD offline Authoring API did not become ready within the bounded startup window.'

install -m 0644 "$ROOT/ops/preview-domain/nginx-app.parser.xdr.ooo.conf" "$STAGED"
nginx -t
systemctl reload nginx

wait_for_domain_route() {
  local attempt http_status https_response https_status
  # A successful systemctl reload only acknowledges the signal. Nginx can
  # briefly serve the old default Exporter TLS certificate from existing workers.
  # Always verify the real hostname/SNI and public CA chain. Never use -k.
  for attempt in {1..40}; do
    http_status=$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' \
      --resolve "$SITE:80:127.0.0.1" "http://$SITE/" --max-time 4 2>/dev/null) ||
      http_status=TRANSPORT_ERROR
    https_response=$(curl --noproxy '*' -sS \
      -w $'\n__PARSER_HTTP_CODE__%{http_code}' \
      --resolve "$SITE:443:127.0.0.1" "https://$SITE/" --max-time 4 2>/dev/null) ||
      https_response=''
    if [[ "$https_response" == *$'\n__PARSER_HTTP_CODE__'* ]]; then
      https_status="${https_response##*$'\n__PARSER_HTTP_CODE__'}"
    else
      https_status=TLS_OR_TRANSPORT_ERROR
    fi
    if [[ "$http_status" == 301 && "$https_status" == 200 &&
          "$https_response" == *"<title>Parser Studio"* ]]; then
      printf 'Verified HTTPS site with hostname validation after probe %s.\n' "$attempt"
      return 0
    fi
    sleep 1
  done
  printf 'Domain route not ready after 40 probes: HTTP=%s HTTPS=%s.\n' \
    "$http_status" "$https_status" >&2
  printf 'Nginx reload or certificate/SNI routing may be wrong; do not disable TLS verification.\n' >&2
  return 1
}
wait_for_domain_route || die 'HTTPS site failed exact-hostname TLS and content validation.'
completed=1
printf '\nHTTPS setup complete. HTTP redirects to HTTPS; no site login is required.\n'
printf 'Open https://%s/ in a browser.\n' "$SITE"
printf 'No Stellar DP parser installation or sensor transmission was performed.\n'
