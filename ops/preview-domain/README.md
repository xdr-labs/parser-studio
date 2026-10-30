# Parser Studio — no-login HTTPS domain

## Scope and confirmed diagnosis

Serve Parser Studio at **https://app.parser.xdr.ooo/** on dev-atlas **without any login page, preview account, or HTTP Basic authentication**. The owner specifically requires a no-login tool. Preserve the existing `exporter.xdr.ooo` service and its configuration.

The DNS A record already resolves to `221.139.249.116`. Previously, HTTP returned Nginx **404** because only the `exporter.xdr.ooo` site was configured; HTTPS returned **401** from the unrelated Exporter host. These responses are not fixed until the site is actually installed and externally verified.

## Bounded site topology

| Component | Address | Purpose |
| --- | --- | --- |
| Nginx | `app.parser.xdr.ooo:80,443` | HTTP 301 to HTTPS, no login, separate virtual host |
| Web UI | `/var/www/parser-studio-app` | Pinned production Vite build, not the development server |
| Offline authoring API | `127.0.0.1:4305` | New same-HEAD service, only offline parser-pairs API |
| Multi-Pass source engine | `127.0.0.1:4304` | New same-HEAD source analysis service, no native DP/sensor access |

The previous `6571` server may be running an older build; it is **not** used by this installation. Both new services bind to loopback; Nginx allows only `/api/v1/parser-pairs/` plus the two bounded `/api/v1/multipass/preview*` routes. Unmatched `/api/` paths return 404. Nginx rejects unwanted POST `Origin` values; it does **not** introduce any user authentication. HTTPS, payload limits and service isolation remain enabled.

This is a public, no-login, stateless authoring endpoint. Do not paste confidential customer log content without authorization. No automatic LLM transfer, application-initiated sensor forwarding, or DP upload/readback is provided.

## Completed nonprivileged verification

```bash
cd /home/aella/parser-studio-secure-domain-20261019
bash -n ops/preview-domain/install-private-preview.sh
bash -n ops/preview-domain/prepare-private-preview.sh
python3 tests/test_preview_nginx_routing_20261019.py -v
python3 tests/test_preview_domain_wait_20261019.py -v
python3 tests/test_preview_staging_20261019.py -v
python3 tests/test_preview_startup_wait_20261019.py -v
python3 -m unittest discover -s tests -p test_embedded_multipass_service.py -v
python3 -m unittest discover -s tests -p test_csv_logical_framing_20261019.py -v
```

The Nginx test creates an isolated unprivileged HTTPS server with a **temporary test-only certificate**. It checks unauthenticated UI/API HTTP 200, no WWW-Authenticate header, 301 redirect, blocked routes, and rejected cross-origin POST. It does **not** prove external-domain deployment.

The package is built from a clean exact Git HEAD with:

```bash
bash ops/preview-domain/prepare-private-preview.sh
git rev-parse HEAD
```

The ignored `dist/private-preview` package contains exact-HEAD frontend/backend/source-engine files and SHA-256 hashes. Never reuse a package from another HEAD. Previously built packages are preserved rather than overwritten automatically.

## Apply on dev-atlas

The owner has approved configuring the no-login domain. The connected remote terminal cannot execute privileged `sudo` operations; an administrator must run the final installer from an already authorized dev-atlas shell:

```bash
cd /home/aella/parser-studio-secure-domain-20261019
sudo bash ops/preview-domain/install-private-preview.sh "$(git rev-parse HEAD)"
```

The installer requires only the existing server's sudo permission. A **Let's Encrypt contact email** is requested only if a valid, existing certificate is unavailable. It does **not** request, create or store a Parser Studio username or password. It creates the dedicated Nginx site, reuses the existing valid certificate if present, installs two independent loopback services, waits for bounded health probes instead of failing on the first cold-start request, validates `nginx -t`, then reloads Nginx. **After reload, it retries both exact-hostname HTTP/HTTPS routes until HTTP 301 and CA-verified HTTPS 200 with the Parser Studio page title are actually served. It never disables TLS validation.** The old Exporter virtual host is not edited. On installation errors, Nginx routing is restored and new systemd services are disabled.

## Resume after the 2026-10-19 partial installation

The first approved installer issued a Let's Encrypt certificate successfully (expires **2027-01-17**) and copied the exact-HEAD static/frontend/backend/parser payload, but probed `127.0.0.1:4304` before the Python process was listening. Its rollback disabled both new systemd units and removed the new Nginx site. The existing Exporter host remained enabled. Its staged application files and issued certificate were preserved.

**Verified:** previously staged files equal the package byte-for-byte, ignoring only Python's generated `__pycache__`. Running that same parser standalone on an isolated port produced HTTP 200 from `/health`. Journal entries showed systemd started the unit, then the installer cleanup stopped it; they did not show a Python crash.

The installer now runs `check-staged-files.sh` before touching services: it resumes only when all three existing destination trees match the exact package. Missing or modified files fail closed. It then checks and **reuses the existing certificate without any new email or password prompt**, starts the units, and retries each health endpoint for up to 40 probes. If the service actually stops, it reports service status and recent journal lines. The same authorized admin invocation above is used to resume.

The second owner-executed installation confirmed the services were ready (Multi-Pass after probe 2, Authoring after probe 1) and the certificate was reused. `nginx -t` passed, but the immediate HTTPS curl failed certificate hostname verification: the earlier default Exporter TLS identity could still be active immediately after a Nginx reload. The installer rolled back the separate site and service units again; it did **not** corrupt the original Exporter. The fix retries the *actual* domain through the local Nginx listener, checks the real certificate hostname and chain, requires HTTP 301 and HTTPS 200 with the Parser Studio page title, and only declares readiness if every condition passes. If a certificate or routing mismatch persists after the bounded window, deployment still fails closed with diagnostics.

Only the installer script, route-regression tests and documentation changed in this follow-up: the compiled Parser Studio web/backend/parser payload remains the same qualified source. Rebuild the exact-HEAD package using `prepare-private-preview.sh` before rerunning. Do not delete existing staged payload or try to bypass OS permissions.

## Real-domain acceptance (not automatically satisfied by deployment scripts)

1. Unauthenticated `http://app.parser.xdr.ooo/` redirects 301 to HTTPS.
2. Unauthenticated `https://app.parser.xdr.ooo/` returns HTTP **200**, shows the **Parser Studio** UI, and never prompts for a preview login. CSS/JS load successfully.
3. The `/api/v1/parser-pairs/capabilities` endpoint works without authentication; JSON/CEF/Syslog/Zeek bounded analysis and DRAFT creation work after real user clicks.
4. A cross-origin browser POST is rejected (403); unused target/sensor/Test Lab routes are absent (404).
5. The pre-existing `exporter.xdr.ooo` response remains unchanged.
6. Run Playwright Chromium with the real domain and review the full beginner flow before claiming user acceptance.

A passing local Nginx fixture is not a successful public HTTPS deployment, and a successful structural parser result is not proof of native Stellar target compatibility.

## Rollback

If acceptance fails, disable **only** the new `app.parser.xdr.ooo` site, stop the two `parser-studio-preview-*.service` units, run `nginx -t`, reload, and verify that `exporter.xdr.ooo` remains available. Do not disable TLS, loosen source-size bounds, or bypass operating-system privileges.

## Updating the running preview

After the first installation, application updates (web, authoring backend, Multi-Pass) follow `UPDATE_RUNBOOK.md`: baseline, exact-commit build, changed-parts-only install, verification and rollback.
