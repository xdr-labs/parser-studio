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
PASSFILE=/etc/nginx/parser-studio-private.htpasswd

die(){ printf 'FAILED: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die 'Run as root using an already authorized administrator session.'
[[ "$#" == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || die 'Pass the verified exact Git HEAD as the only argument.'
[[ ! -e "$STAGED" && ! -e "$ENABLED" ]] || die 'Domain virtual host already exists; do not overwrite it.'
[[ ! -e "/etc/systemd/system/$SVC" && ! -e "/etc/systemd/system/$BACKEND_SVC" ]] ||
  die 'Preview service already exists; review before changing it.'
[[ ! -e "$WWW" && ! -e "$BACKEND" && ! -e "$MULTIPASS" && ! -e "$PASSFILE" ]] ||
  die 'Existing preview artifacts found; review before changing anything.'
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
[[ -f "$PKG/multipass/multipass_preview_api.py" ]] || die 'Source engine missing.'
( cd "$PKG" && sha256sum --status -c FILES.sha256 ) ||
  die 'Offline preview package failed integrity verification.'
if find "$PKG" -type l -print -quit | grep -q .; then
  die 'Deployment package contains symlinks; copy refused.'
fi
for bin in nginx certbot curl openssl systemctl git; do
  command -v "$bin" >/dev/null || die "Required command missing: $bin"
done
getent hosts "$SITE" | grep -q 221.139.249.116 || die 'DNS does not resolve to this authorized development server.'
if ss -ltn | grep -Eq '127\.0\.0\.1:(4304|4305)[[:space:]]'; then
  die 'Private preview port 4304 or 4305 is already occupied.'
fi

printf '\nThis installs a NEW, password-protected HTTPS Nginx virtual host for %s.\n' "$SITE"
printf 'It requests one TLS certificate, installs a loopback-only parser worker and reloads Nginx.\n'
printf 'It will not modify exporter.xdr.ooo or any application credentials.\n'
read -r -p 'Type DEPLOY-PARSER-STUDIO to authorize this host change: ' approval
[[ "$approval" == DEPLOY-PARSER-STUDIO ]] || die 'Operator did not approve.'
read -r -p "Let's Encrypt contact email: " email
[[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die 'Invalid email.'
read -r -p 'New PRIVATE preview username (letters, digits, _ or -): ' username
[[ "$username" =~ ^[A-Za-z][A-Za-z0-9_-]{2,31}$ ]] || die 'Invalid username.'
read -r -s -p 'New private preview password (at least 12 characters): ' password
printf '\n'
read -r -s -p 'Repeat private preview password: ' again
printf '\n'
[[ "$password" == "$again" && -n "$password" ]] || die 'Passwords do not match.'
[[ "$password" =~ .{12,} ]] || die 'Password too short.'
unset again
encrypted=$(printf '%s' "$password" | openssl passwd -6 -stdin)
unset password

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

certbot certonly --webroot --webroot-path "$ACME" -d "$SITE" \
  --agree-tos --non-interactive --email "$email" --keep-until-expiring

install -d -m 0755 "$WWW" "$BACKEND" "$MULTIPASS"
cp -a "$PKG/web/." "$WWW/"
cp -a "$PKG/backend/." "$BACKEND/"
cp -a "$PKG/multipass/." "$MULTIPASS/"
chmod -R a+rX "$WWW" "$BACKEND" "$MULTIPASS"

printf '%s:%s\n' "$username" "$encrypted" > "$PASSFILE"
chown root:www-data "$PASSFILE"
chmod 0640 "$PASSFILE"
unset encrypted

install -m 0644 "$ROOT/ops/preview-domain/parser-studio-preview-multipass.service" "/etc/systemd/system/$SVC"
install -m 0644 "$ROOT/ops/preview-domain/parser-studio-preview-authoring.service" "/etc/systemd/system/$BACKEND_SVC"
systemctl daemon-reload
systemctl enable --now "$SVC" "$BACKEND_SVC"
curl -fsS --max-time 10 http://127.0.0.1:4304/health >/dev/null ||
  die 'Isolated parser worker did not become ready.'
curl -fsS --max-time 10 http://127.0.0.1:4305/api/v1/parser-pairs/capabilities >/dev/null ||
  die 'Exact-HEAD offline Authoring API did not become ready.'

install -m 0644 "$ROOT/ops/preview-domain/nginx-app.parser.xdr.ooo.conf" "$STAGED"
nginx -t
systemctl reload nginx

http_status=$(curl -sS -o /dev/null -w '%{http_code}' --resolve "$SITE:80:127.0.0.1" "http://$SITE/" --max-time 8)
https_status=$(curl -sS -o /dev/null -w '%{http_code}' --resolve "$SITE:443:127.0.0.1" "https://$SITE/" --max-time 10)
[[ "$http_status" == 301 && "$https_status" == 401 ]] ||
  die "Unexpected HTTP/HTTPS unauthenticated status: $http_status/$https_status."
completed=1
printf '\nHTTPS setup complete. HTTP redirects to HTTPS and HTTPS is protected by Basic authentication.\n'
printf 'Domain: https://%s/\nAccess username: %s\n' "$SITE" "$username"
printf 'Enter the password you just configured in your browser. No credential was printed or logged.\n'
printf 'The application is still a PRIVATE development preview; this does not approve production or Stellar DP installation.\n'
