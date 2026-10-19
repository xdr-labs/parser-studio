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

The installer requires only the existing server's sudo permission and a **Let's Encrypt certificate contact email**. It does **not** request, create or store a Parser Studio username or password. It creates the dedicated Nginx site, requests the domain TLS certificate through Certbot webroot, installs the exact-HEAD build plus two independent loopback services, validates `nginx -t`, then reloads Nginx. The old Exporter virtual host is not edited. On an installation error, it restores Nginx routing and disables the new systemd services; copied staging artifacts remain for review.

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
