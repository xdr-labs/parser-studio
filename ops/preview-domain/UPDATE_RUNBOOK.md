# Development Preview update runbook (deploy, verify, roll back)

Scope: routine updates of the public **Development Preview** at https://app.parser.xdr.ooo/ on `dev-atlas`.
This is not a Stellar Cyber DP, a customer environment or a production release. A production or tenant
release needs its own owner approval and is out of scope here.

The first installation (Nginx site, systemd units, TLS) is described in `README.md` and is done once by the
owner. This runbook only covers replacing the application files afterwards. Do not edit the Nginx site,
the systemd units, TLS certificates, `training/`, the favicons or any file outside the paths below.

## 1. Targets

| Part | Location | How it is served | Changes when |
| --- | --- | --- | --- |
| Web UI | `/var/www/parser-studio-app` (`index.html`, `assets/`) | Nginx static files | anything under `src/`, `index.html`, `public/` |
| Authoring backend | `/opt/parser-studio-preview/backend/dist` | `parser-studio-preview-authoring.service`, `127.0.0.1:4305` | anything under `backend/` |
| Multi-Pass engine | `/opt/parser-studio-preview/multipass` | `parser-studio-preview-multipass.service`, `127.0.0.1:4304` | anything under `runtime/multipass/` |

Facts that shape the procedure:

- Both services run as the Unix user `aella` with `Restart=on-failure`. Files in the paths above are owned by `aella`.
- Nginx sends `Cache-Control: private, no-store`, so no cache purge is needed.
- `assets/` keeps older hashed bundles on purpose. New bundles are added next to them, so rolling back
  `index.html` alone restores the previous web version. Do not delete old assets as part of an update.
- There is no CI deploy job. `.github/workflows/quality.yml` only tests. Deployment is manual.
- Old scripts in `/home/aella/.local/state/parserstudio-public-rollouts/` are pinned to one Git HEAD and
  specific file hashes. They are history and templates, not tools: never run them against a new version.

## 2. Preconditions

1. Read `AGENTS.md` and `.engineering/project.yaml`. Confirm that the owner approved updating the
   Development Preview for this change.
2. The change is merged into `main` and you know the exact commit: `HEAD=<40-hex sha>`.
3. Local checks on that commit pass: `npx tsc --noEmit -p .` and `npx vitest run`.
   The `quality` workflow does not run on `main` after a merge, so run these yourself.
4. Record the current state before touching anything (section 3).

Run commands from `dev-atlas`. File work happens as `aella`. Only `systemctl restart` needs root.
If you inspect an `aella`-owned checkout as root, wrap git in `runuser -u aella -- git ...`
(otherwise git stops with "dubious ownership").

## 3. Record the baseline

```bash
STATE=/home/aella/.local/state/parserstudio-public-rollouts
REL=$STATE/release-<short-sha>-$(date -u +%Y%m%d)
install -d -o aella -g aella -m 700 $REL

{ echo "utc $(date -u +%FT%TZ)"
  echo "live index: $(sha256sum /var/www/parser-studio-app/index.html | cut -c1-64)"
  echo "public index: $(curl -fsS -H 'Cache-Control: no-cache' https://app.parser.xdr.ooo/ | sha256sum | cut -c1-64)"
  for s in authoring multipass; do u=parser-studio-preview-$s.service
    echo "$u active=$(systemctl is-active $u) pid=$(systemctl show $u -p MainPID --value) restart=$(systemctl show $u -p Restart --value)"; done
  echo "4305: $(curl -fsS -m 5 http://127.0.0.1:4305/health)"
  echo "4304: $(curl -fsS -m 5 http://127.0.0.1:4304/health)"
  (cd /var/www/parser-studio-app && find . -type f -not -path './training/*' | sort | xargs sha256sum)
} > $REL/baseline-before.txt
```

Stop if the live index hash and the public index hash differ, if a service is not `active`, or if a
health endpoint does not answer `{"status":"ok",...}`. Find out why before deploying. Also find out which
commit is live: the newest `static-deployment-receipt.json` / `deployment-receipt.json` under
`/home/aella/.local/state/` names it. If you cannot name the live commit, say so in the receipt.

## 4. Build the candidate from the exact commit

Build in a clean checkout, never from a working tree with local edits:

```bash
cd /home/aella/.dev/parserstudio-core        # shared clone; any clean clone works
runuser -u aella -- git fetch origin main
runuser -u aella -- git worktree add --detach $REL/src <HEAD>
runuser -u aella -- git -C $REL/src rev-parse HEAD HEAD^{tree}     # record both

# as aella, in the background if it may exceed the 30 s command limit of the DR Link shell
cd $REL/src && npm ci --no-audit --no-fund && npm run build                 # Web: dist/
cd $REL/src/backend && npm ci --no-audit --no-fund && npm run build        # Backend: backend/dist/
```

`npm ci` prints "install-scripts ... esbuild" warnings. They are harmless: the build still succeeds.
Multi-Pass has no build step; its source is `runtime/multipass/*.py`.

## 5. Decide what changed (deploy only that)

Compare the candidate with what is installed, by content hash:

```bash
cd $REL/src && python3 - <<'EOF'
import hashlib,os
def inv(root):
    d={}
    for dp,_,fs in os.walk(root):
        for f in fs:
            p=os.path.join(dp,f); r=os.path.relpath(p,root)
            if r.startswith('training/') or '/node_modules/' in '/'+r: continue
            d[r]=hashlib.sha256(open(p,'rb').read()).hexdigest()
    return d
live,new=inv('/var/www/parser-studio-app'),inv('dist')
print('WEB new files   ',sorted(set(new)-set(live)))
print('WEB changed     ',sorted(k for k in new if k in live and new[k]!=live[k]))
bl,bn=inv('/opt/parser-studio-preview/backend/dist'),inv('backend/dist')
print('BACK new files  ',sorted(set(bn)-set(bl)))
print('BACK only live  ',sorted(set(bl)-set(bn)))
print('BACK changed    ',sorted(k for k in bn if k in bl and bn[k]!=bl[k]))
EOF
diff -rq -x __pycache__ $REL/src/runtime/multipass /opt/parser-studio-preview/multipass
```

Expected for a web-only change: a new `assets/index-<hash>.js` plus a changed `index.html`; nothing in the
backend and Multi-Pass comparisons. Anything unexpected (a changed CSS, a missing live file, a backend
file other than the ones the change touched) is a reason to stop and look, not to push on.
Files under `backend/dist/test/` are compiled tests that never run in the service; differences there
(for example `test/mixed-csv.test.js`) are known and not a runtime change.

Restart a service only if its own files changed. Web-only updates must not restart either service.

## 6. Back up, then install

Install in this order. Each step is reversible with section 8.

1. **Back up** the live files you will replace:
   ```bash
   mkdir -m 700 $REL/rollback && chown aella:aella $REL/rollback
   cp -p /var/www/parser-studio-app/index.html $REL/rollback/index.html
   cp -a /opt/parser-studio-preview/backend/dist $REL/rollback/backend-dist       # if the backend changes
   ( cd $REL/rollback/backend-dist && find . -type f | sort | xargs sha256sum ) > $REL/rollback/backend-dist.sha256
   # if Multi-Pass changes: cp -p each changed .py into $REL/rollback/multipass/
   ```
2. **Backend** (only if it changed). Swap the whole `dist` directory by rename, so there is never a half-written tree:
   ```bash
   B=/opt/parser-studio-preview/backend
   cp -a $REL/src/backend/dist $B/.dist_candidate_<short-sha>
   mv $B/dist $B/.dist_rollback_<short-sha>
   mv $B/.dist_candidate_<short-sha> $B/dist
   systemctl restart parser-studio-preview-authoring.service        # root
   for i in $(seq 1 40); do [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1:4305/health)" = 200 ] && break; sleep 0.8; done
   ```
   If health never returns 200, go straight to section 8.
3. **Multi-Pass** (only if it changed). Install the changed `.py` files atomically (copy to a temporary name in the
   same directory, then `mv -f`), then `systemctl restart parser-studio-preview-multipass.service` and wait for
   `http://127.0.0.1:4304/health` to return 200.
4. **Web**. Add the new bundle first, switch `index.html` last. Both with a temporary name and `mv -f`, so the switch is atomic:
   ```bash
   W=/var/www/parser-studio-app
   install -o aella -g aella -m 644 $REL/src/dist/assets/index-<hash>.js $W/assets/.new.js && mv -f $W/assets/.new.js $W/assets/index-<hash>.js
   install -o aella -g aella -m 644 $REL/src/dist/index.html $W/.new.idx && mv -f $W/.new.idx $W/index.html
   ```
   If other new files appear in step 5 (for example a changed CSS or worker), add them before `index.html` the same way.
   Never overwrite an existing hashed asset with different content.

A tested example of these steps as one fail-closed script that rolls itself back is kept next to the
receipt of the 2026-10-30 update: `$STATE/release-35dc3eb-20261030/deploy.sh` (pinned to that commit; copy
the structure, not the hashes).

## 7. Verify

Immediately after install:

```bash
curl -fsS -H 'Cache-Control: no-cache' https://app.parser.xdr.ooo/ | sha256sum          # must equal sha256 of $REL/src/dist/index.html
curl -fsS https://app.parser.xdr.ooo/assets/index-<hash>.js | sha256sum                  # must equal the built file
curl -s -o /dev/null -w '%{http_code}\n' https://app.parser.xdr.ooo/assets/index-B1nKBdrH.css   # 200 (use the current css name)
systemctl is-active parser-studio-preview-authoring.service parser-studio-preview-multipass.service
systemctl show parser-studio-preview-multipass.service -p MainPID --value     # unchanged unless Multi-Pass was deployed
curl -fsS http://127.0.0.1:4305/health; curl -fsS http://127.0.0.1:4304/health
```

Then run a real-browser check on the public URL (Playwright CLI), as a beginner would use it:

1. Auto Parser: paste a small sample, fill manufacturer/product/version/port, Analyze Logs, Review Fields, Map Fields,
   Create Parser. The result must be reachable and the `.conf` must show the chosen port.
2. ChatGPT Assisted Parser: Prepare ChatGPT Prompt, check a stored ChatGPT answer, Test Proposed Fix, Apply.
   This exercises `/api/v1/parser-pairs/*` on the backend.
3. Check the change itself on screen (the text or behavior the update is about).
4. No page errors, and only requests to `app.parser.xdr.ooo`.

Do not call a deploy done on hash checks alone: the browser pass is what proves a beginner can use it.
Use only sample logs without customer data.

## 8. Roll back

Roll back on any failed check in sections 6 or 7, or when the owner asks.

```bash
REL=<the release directory used for the update>
W=/var/www/parser-studio-app; B=/opt/parser-studio-preview/backend

# 1. Web: restore the previous index.html (old assets are still in assets/)
cp -p $REL/rollback/index.html $W/.idx.rb && chown aella:aella $W/.idx.rb && mv -f $W/.idx.rb $W/index.html

# 2. Backend (only if it was changed): swap back and restart
mv $B/dist $B/.dist_failed_<short-sha>
mv $B/.dist_rollback_<short-sha> $B/dist          # or: cp -a $REL/rollback/backend-dist $B/dist
systemctl restart parser-studio-preview-authoring.service
# wait for http://127.0.0.1:4305/health = 200

# 3. Multi-Pass (only if it was changed): restore the .py files from $REL/rollback/multipass/, restart its service, wait for 4304 health
```

After a rollback, repeat the checks of section 7 against the previous release: the public `index.html`
hash must equal `baseline-before.txt`, `diff -r` of the backend against `$REL/rollback/backend-dist` must be
empty, and both health endpoints must answer. Leave the failed candidate in place under its `.dist_failed_*`
name for diagnosis. Keep the rollback directory; it is the evidence.

## 9. Record the receipt

Write `deployment-receipt.json` into `$REL` with at least: UTC time, repository, deployed commit and tree,
previous commit (if known), which of web / backend / Multi-Pass changed, old and new `index.html` SHA-256, new
bundle name and SHA-256, service PIDs before and after (the Multi-Pass PID must be unchanged for a web-only
update), rollback paths, local test counts, and the paths of the browser evidence. Do not store secrets or
customer logs in it.

## 10. Do not

- Do not change the Nginx site, systemd units, TLS certificates or security headers as part of an update.
- Do not delete `training/`, favicons, older hashed assets, older `.dist_rollback_*` directories or earlier receipts.
  Pruning old rollback material is a separate decision for the owner.
- Do not restart a service that did not change, and do not deploy untested or unmerged code.
- Do not run an old pinned rollout script against a new version.
- Do not describe the Development Preview as production, and do not claim Stellar Cyber or native Fluentd
  compatibility from a deploy check: those remain NOT VERIFIED.

## Appendix: reference run

2026-10-30, Development Preview, web + backend update from `f960030` (PR #168) to `35dc3eb` (PRs #169 to #182).
Changed: `assets/index-Dlm8aAWh.js` (new) and `index.html` in the web root; `templates/ruby-fragment.rb.tpl` in the backend `dist` (plus compiled test files).
Multi-Pass unchanged (PID stayed the same). Backend PID changed once, on purpose. Public check: HTML and JS hashes equal the built files, CSS and favicon answered 200, both health endpoints 200, browser pass without page errors.

2026-10-30 (later), web-only update to `2f86e6e` (PR #184). Changed: `assets/index-CdF6lDMm.js` (new) and `index.html`; the backend and Multi-Pass comparisons were empty and no service was restarted. The same update served as a **rollback drill** of section 8 on the live preview: roll back (under one second, public `index.html` equal to the previous hash, old behavior visible again in the browser), then apply again and verify. The drill covered the web part only; swapping the backend `dist` back has not been exercised on the live service. The script pair used (`build.sh`, `deploy_web.sh apply|rollback`) is kept in `$STATE/release-2f86e6e-20261030/`; it is the shortest example for a web-only update.
