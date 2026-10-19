# Private HTTPS Preview: app.parser.xdr.ooo

## Incident and boundary

Verified on dev-atlas (2026-10-19):
- `app.parser.xdr.ooo` resolved to `221.139.249.116`.
- HTTP returned Nginx 404. HTTPS returned 401 with the **Stellar Data Exporter** realm.
- `/etc/nginx/sites-enabled/` contained only `exporter.xdr.ooo`; Parser Studio had no virtual host.
- Existing internal Parser Studio frontend `127.0.0.1:6570` returned HTTP 200 and offline authoring API `127.0.0.1:6571` served its scoped capabilities.
- This ChatGPT development connection was **denied** permission to use `sudo`. Do not switch identities, bypass the device permission, or claim the domain is fixed without the administrator action.

This is an **operator-approved, private development preview**, not public anonymous access, a product release, or Stellar native/DP/tenant validation. It requires an explicit administrator execution, owner acceptance and security signoff before any wider exposure.

## Implementation

- An independent Nginx virtual host for `app.parser.xdr.ooo`. Existing `exporter.xdr.ooo` files are never changed.
- HTTP serves only ACME challenges and redirects other requests to HTTPS.
- Certbot obtains an independent TLS certificate via HTTP-01/webroot.
- HTTPS uses a new, separately chosen Nginx Basic credential (SHA-512-crypt), never reused from the Exporter.
- `POST` requires the exact browser `Origin: https://app.parser.xdr.ooo` at the Nginx boundary; forged and cross-origin submissions return HTTP 403.
- Browser static assets are read-only and root-owned under `/var/www/parser-studio-app`.
- The scoped, preexisting offline-authoring API remains loopback-only on `127.0.0.1:6571`.
- The bounded source preview runs as a dedicated, unprivileged systemd service on `127.0.0.1:4304` and accepts the exact HTTPS origin only when explicitly configured. No other device/tenant API is routed through Nginx.
- The installer checks the **exact Git HEAD** and independently created frontend build marker. Existing paths cause fail-closed termination. Failure rolls back only the newly created host configuration and service.

## Qualify and install

Only run these commands after the candidate is committed and its exact-HEAD tests/CI have been reviewed:

```bash
cd /home/aella/parser-studio-secure-domain-20261019
npm run build
git rev-parse HEAD
printf '%s\n' "$(git rev-parse HEAD)" > dist/.parser-studio-built-head
```

Once the owner/operator explicitly authorizes the privileged host change, run **in an already trusted dev-atlas administrator shell**:

```bash
sudo bash /home/aella/parser-studio-secure-domain-20261019/ops/preview-domain/install-private-preview.sh <exact-40-character-SHA>
```

The installer interactively requests an authorization phrase, certificate contact email, a new preview username, and a private password of at least 12 characters. **Never paste this password in ChatGPT or terminal command-line arguments.** No existing Exporter authentication is copied or bypassed.

## Required live validation

1. `curl -I http://app.parser.xdr.ooo/` must return **301** to `https://app.parser.xdr.ooo/`.
2. `curl -I https://app.parser.xdr.ooo/` without credentials must return **401** with **Parser Studio private development access**, not **Stellar Data Exporter**.
3. A trusted owner browser enters the newly created preview credentials; the two-path Parser Studio UI loads from the correct origin and does not show a Vite allowed-host error.
4. Perform the real browser flow using approved synthetic vendor-style logs: paste → Analyze Logs → review PARTIAL/residual regions → CSV/Zeek schema review → Stellar mappings → final sample test → download uninstalled DRAFT. Also test the manual-redacted ChatGPT path.
5. Confirm blocked requests: wrong Origin POST **403**, unsupported `/api/v1/test-lab` and target/sensor paths **404**; do not test real target/sensor operations.
6. Check saved Local Versions are origin/profile scoped. No automatic source transfer.
7. Compare original `exporter.xdr.ooo` service and virtual host behavior with its previously captured expected result.

## Rollback (administrator only)

If a privileged installation is interrupted, the script attempts to remove only the newly added Parser Studio virtual host and service, tests Nginx and reloads it. A certificate already issued by Certbot may remain; review separately.

After a *completed* install, a rollback must be separately approved by the owner. The operator should disable `parser-studio-preview-multipass.service`, disable the **Parser Studio-only** enabled Nginx symlink, validate `nginx -t` and reload Nginx. Do not remove or change `exporter.xdr.ooo`, the existing authoring service, certificates used by other sites, or unrelated user worktrees.

## Evidence classification

The local isolated Nginx integration test provisions its own self-signed TLS certificate and ephemeral loopback ports to verify HTTP redirect, HTTPS authentication, exact-origin POST, and denied API routes without touching ports 80/443. **Its PASS does not prove the public site is live.** A real certificate and privileged virtual host installation remain required.
