# Parser Studio — private domain preview

## Purpose

Serve the **existing beta candidate** at `https://app.parser.xdr.ooo` on **dev-atlas**, behind newly created password-protected HTTPS Nginx routing. This is **not a production release**, a Stellar Cyber native import claim, or permission to send data to devices.

Current confirmed baseline (2026-10-19):
- `app.parser.xdr.ooo` DNS -> `221.139.249.116`.
- HTTP `http://app.parser.xdr.ooo/` returns **404**, because Nginx only enables the unrelated `exporter.xdr.ooo` virtual host.
- HTTPS returns the **existing Exporter 401**, not Parser Studio.
- Local Parser Studio UI and offline compiler already exist as separate local services. The existing 6571 compiler was started from an older candidate, so **do not expose 6571**.
- No owner-approved public domain routing, TLS issuance, credentials, installation or Full User E2E has taken place.

## Delivery topology

| Component | Address | Boundary |
| --- | --- | --- |
| Nginx `app.parser.xdr.ooo` | 80 -> 443, HTTPS with HTTP Basic auth | New independent site, never edit `exporter.xdr.ooo` |
| Browser static Web UI | `/var/www/parser-studio-app` | Exact SHA built `web/` package, no Vite development server |
| Offline authoring API | `127.0.0.1:4305` | New exact-SHA systemd service; only `/api/v1/parser-pairs/` |
| Multi-Pass source parser | `127.0.0.1:4304` | New exact-SHA Python systemd service; explicit HTTPS Origin allowlist |
| Authenticated browser | `https://app.parser.xdr.ooo/` | No app-originated DP upload/sensor send or automatic AI log transfer |

Nginx rejects cross-origin/missing-Origin POST requests before the local backend and denies any `/api/` path outside the stated allowlist. Both services bind localhost. The user supplies the preview password directly in the administrator shell; it is **not** written to Git, logged, or forwarded to the assistant. HTTPS remains the only browsing entrypoint. TLS certificate issuance and password creation constitute separate privileged approval gates.

## Nonprivileged qualification and packaging

From the isolated `/home/aella/parser-studio-secure-domain-20261019` worktree at a committed, clean exact HEAD:

```bash
cd /home/aella/parser-studio-secure-domain-20261019
bash -n ops/preview-domain/install-private-preview.sh
bash -n ops/preview-domain/prepare-private-preview.sh
python3 tests/test_preview_nginx_routing_20261019.py -v
python3 -m unittest discover -s tests -p test_embedded_multipass_service.py -v
python3 -m unittest discover -s tests -p test_csv_logical_framing_20261019.py -v
bash ops/preview-domain/prepare-private-preview.sh
git rev-parse HEAD
```

The prepare script compiles Web UI and backend, prepares **production-only AJV dependencies**, records an exact Git SHA, and writes a checksummed package under the ignored `dist/private-preview/`. It does not modify Nginx, systemd, TLS, credentials, or running services. Do not use an uncommitted or stale source build. Each new candidate SHA must have its own qualified package; do not overwrite an existing package implicitly.

## Privileged installation — **owner action and separate authorization required**

Only after explicit owner authorization to **create this private development host**, and after inspecting all generated files, the owner uses an already authorized root/admin session on dev-atlas:

```bash
cd /home/aella/parser-studio-secure-domain-20261019
git rev-parse HEAD
sudo bash ops/preview-domain/install-private-preview.sh "$(git rev-parse HEAD)"
```

The installer validates SHA/checksums, existing file/port collisions, DNS, required binaries, and separate virtual-host boundaries before it can proceed. It **interactively** asks for `DEPLOY-PARSER-STUDIO`, a Let's Encrypt contact email, and a newly chosen *private preview* username/password. It requests the certificate through HTTP-01 webroot, installs the static/UI/backend/Multi-Pass package under new paths, creates two loopback-only systemd services, tests `nginx -t`, and finally reloads Nginx. The pre-existing Exporter host config is neither edited nor replaced. If a step fails, the installer removes its Nginx routing and disables its new service units; newly copied preview files and any issued certificate remain for review rather than automatically deleting data.

## Owner and browser acceptance — not yet PASS

Verify the **actual external** response, not just the isolated tests:

1. `http://app.parser.xdr.ooo/` redirects **301** to `https://app.parser.xdr.ooo/`.
2. Unauthenticated HTTPS returns **401** for Parser Studio, not the `Stellar Data Exporter` Basic realm.
3. After the owner enters the new preview password, the real Parser Studio Auto Parser and ChatGPT Assisted Parser pages load with HTTP **200**, scripts/CSS load, and no browser exceptions.
4. Verify 1 JSON, 1 CEF/LEEF, 1 wrapped Syslog, multi-event JSON, and Zeek prepared TAB CSV with confirmation. Check raw text/source accounting, field mapping, browser-only versions, ChatGPT manual redaction, and downloadable DRAFT; no Stellar/DP installation.
5. Run blocked-route tests (`/api/v1/test-lab/`, `/api/v1/targets/`): **404**. Anonymous API: **401**. Unauthorized-origin POST: **403**.
6. Confirm Exporter still answers identically to its pre-change baseline and record the exact candidate SHA, Browser PASS/FAIL and Nginx access results. Owner visual acceptance is distinct from synthetic Chromium test PASS.

The isolated test at `tests/test_preview_nginx_routing_20261019.py` runs Nginx on temporary unprivileged ports with a throwaway local certificate and test-only password. That isolated green result **does not establish public-domain deployment, Let's Encrypt validity, or owner acceptance**.

## Rollback

If the actual domain acceptance fails, an approved administrator should disable only the new `app.parser.xdr.ooo` site and stop the two `parser-studio-preview-*.service` units, run `nginx -t`, reload Nginx, and verify that `exporter.xdr.ooo` is unchanged. Preserve site/certificate/auth files until the failure is understood. Never replace the existing Exporter virtual host or bypass SSH/OS privilege, TLS certificate verification, origin checks, or browser authentication to force a PASS.
