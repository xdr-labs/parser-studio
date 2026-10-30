#!/bin/bash
# Development Preview, web-only update (new JS/CSS assets + index.html). Modes: apply | rollback. Fail-closed; apply rolls itself back.
set -uo pipefail
MODE=${1:-}
REL=@REL@
SRC=$REL/src; WEB=/var/www/parser-studio-app; BK=$REL/rollback
HEADSHA=@HEADSHA@
OLD_INDEX=@OLD_INDEX@
AUTH=parser-studio-preview-authoring.service; MP=parser-studio-preview-multipass.service
sha(){ sha256sum "$1" | cut -c1-64; }
log(){ echo "$(date -u +%FT%TZ) [$MODE] $*" | tee -a $REL/deploy.log; }
rollback(){
  log "ROLLBACK"
  [ -f $BK/index.html ] || { log "no backup index"; return 1; }
  cp -p $BK/index.html $WEB/.idx.rb && chown aella:aella $WEB/.idx.rb && chmod 644 $WEB/.idx.rb && mv -f $WEB/.idx.rb $WEB/index.html
  local got; got=$(curl -fsS -H 'Cache-Control: no-cache' https://app.parser.xdr.ooo/ | sha256sum | cut -c1-64)
  log "after rollback: file=$(sha $WEB/index.html) public=$got want=$OLD_INDEX"
  [ "$got" = "$OLD_INDEX" ]
}
fail(){ log "FAIL: $*"; rollback; exit 1; }
[ "$(id -u)" = 0 ] || { echo need root; exit 2; }
case $MODE in
rollback) rollback && log "ROLLBACK_PASS" || { log "ROLLBACK_MISMATCH"; exit 1; }; exit 0;;
apply) ;;
*) echo "usage: $0 apply|rollback"; exit 2;;
esac
[ "$(runuser -u aella -- git -c safe.directory='*' -C $SRC rev-parse HEAD)" = $HEADSHA ] || fail "source HEAD"
[ "$(sha $WEB/index.html)" = $OLD_INDEX ] || { log "live index is not the recorded previous release"; exit 1; }
[ "$(systemctl is-active $AUTH)" = active ] && [ "$(systemctl is-active $MP)" = active ] || { log "service inactive before apply"; exit 1; }
if [ -e $BK ]; then [ "$(sha $BK/index.html)" = $OLD_INDEX ] || { log "existing backup is not the previous index"; exit 1; }
else mkdir -m 700 $BK; chown aella:aella $BK; cp -p $WEB/index.html $BK/index.html; fi
AP=$(systemctl show $AUTH -p MainPID --value); MPP=$(systemctl show $MP -p MainPID --value)
NEWASSETS=$(cd $SRC/dist && find assets -type f | sort)
for a in $NEWASSETS; do
  if [ -e $WEB/$a ]; then [ "$(sha $WEB/$a)" = "$(sha $SRC/dist/$a)" ] || fail "asset collision $a"; continue; fi
  install -o aella -g aella -m 644 $SRC/dist/$a $WEB/.new.asset && mv -f $WEB/.new.asset $WEB/$a || fail "asset install $a"
  log "installed $a"
done
install -o aella -g aella -m 644 $SRC/dist/index.html $WEB/.new.idx && mv -f $WEB/.new.idx $WEB/index.html || fail "index install"
[ "$(curl -fsS -H 'Cache-Control: no-cache' https://app.parser.xdr.ooo/ | sha256sum | cut -c1-64)" = "$(sha $SRC/dist/index.html)" ] || fail "public index mismatch"
for a in $NEWASSETS; do
  [ "$(curl -fsS https://app.parser.xdr.ooo/$a | sha256sum | cut -c1-64)" = "$(sha $SRC/dist/$a)" ] || fail "public asset mismatch $a"
done
[ "$(curl -s -o /dev/null -w '%{http_code}' https://app.parser.xdr.ooo/favicon.svg)" = 200 ] || fail "public favicon"
[ "$(systemctl show $AUTH -p MainPID --value)" = "$AP" ] && [ "$(systemctl show $MP -p MainPID --value)" = "$MPP" ] || fail "a service restarted unexpectedly"
curl -fsS http://127.0.0.1:4305/health >/dev/null && curl -fsS http://127.0.0.1:4304/health >/dev/null || fail "health"
log "APPLY_PASS head=$HEADSHA index=$(sha $WEB/index.html) authoringPid=$AP multipassPid=$MPP (both unchanged)"
