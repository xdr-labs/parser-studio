# Parser Studio backend — R1.5/R3 synthetic native parser qualification

**Ownership:** Backend only. Other session owns the Web UI in Draft PR #3. This branch deliberately changes only `backend/**` (the denied workflow lives only as a template under `backend/docs/`); it does not modify any UI, legacy docs, remote td-agent or production target.

## Supported, precisely

- Strict, version-neutral `ParserProject` 0.1 JSON Schema in [schema/parser-project.v0.1.schema.json](schema/parser-project.v0.1.schema.json).
- Supported subset: JSON, strict quoted KV, CSV, RFC5424 Syslog (optional JSON/KV/CEF/LEEF body), standalone CEF and LEEF. Typed top-level/nested/vendor field mapping supports `string`, `integer`, `ip`, `port`, `boolean` and ISO8601 timestamps requiring an explicit timezone.
- Ordered classification by `equals` or `exists` (including enriched output), default `syslog`, and generated `stellar_log_index`. Allowlisted no-code enrichments: `set_const`, `copy`, `lowercase`, `uppercase`. Typed field errors include stage and input field path without leaking log content.
- UDP/TCP source blocks, host-reference custom parser type/tag, transport settings include and rewrite-tag routing.
- Deterministic compiler produces two files, **`customized_<slug>.conf` and extensionless `customized_<slug>`**, with SHA-256 and an explicitly **DRAFT** manifest.
- Local stateless HTTP validate/generate/schema **and safe read-only pair inspection** endpoints for the separate UI. No file writes from API. Only byte-for-byte self-generated pairs become editable projects; arbitrary vendor Ruby stays opaque.
- Project-local pinned Ruby 3.2.3 + Fluentd 1.17.1 synthetic qualification passes Node tests, ten Ruby syntax profiles, pure Ruby callbacks, Fluentd Parser Plugin API and Fluentd config grammar checks. A shared pre-execution SHA-256 guard checks all ten generated Ruby/CONF profiles against current-HEAD import/recompile evidence before any Ruby class evaluation; the local attestation is not a hardened sandbox. This is **not** vendor's extensionless-source wrapper/loader import or Stellar Cyber installation. The pending CI workflow is only a template because the current OAuth token lacks workflow modification scope.

**Optional offline private-fixture preparation:** A local-only preflight validates strictly bounded private golden-event JSON shape and local filesystem permissions without executing Ruby, persisting reports, transferring log content, or creating an HTTP endpoint. See [private fixture preflight](docs/PRIVATE_FIXTURE_PREFLIGHT.md). Its success is NOT native or Stellar import verification.

**Not supported yet:** proprietary vendor loader/portal adapters, live UDP/TCP listener or transport-include behavior, general regex/Grok editing, arbitrary Ruby, deeply customized CEF/LEEF edge cases, RFC3164, HTTP receiver, multi-line parsing, private raw-event fixtures, production deployment. The asset is a Ruby **fragment**, not a standalone Fluentd plugin. The manifest must never claim `ENGINE_TESTED` or `TARGET_IMPORT_VERIFIED` based solely on Ruby harness tests.

## Run

```sh
cd backend
npm ci
npm run check
npm test
npm run build
npm start                  # listen only on 127.0.0.1:4179
```

For full synthetic native qualification, install the pinned Ruby Gemfile.lock in a disposable runner and execute:

```sh
bash scripts/qualify.sh
```

The pinned Fluentd Parser API suite additionally checks 22 **independently authored public synthetic golden events** across the ten generated profiles against full expected normalized records, including event timestamps and sanitised failure paths. The committed fixture set is under test_native/fixtures; no real customer/vendor raw log is committed. Separate ignored synthetic-import and synthetic-golden reports include exact source hashes. Successful synthetic replay is **not** a real target loader or customer raw-log E2E.

The suite writes `.tmp/synthetic-native-report.json` with SHA-256 provenance and explicit `targetImportVerified:false`. It exercises Fluentd's real Parser Plugin API and config syntax but **does not** install a plugin, open a live listener, or validate Stellar Cyber imports. See [native qualification](docs/NATIVE_QUALIFICATION.md) and [CI permissions](docs/CI_SETUP.md).

## Web UI contract

See [complete API contract](docs/API_CONTRACT.md) for all form fields, additional log formats, supported enrichment operations, input limits, errors, and honest export readiness.

All API input/output is UTF-8 JSON; **no CORS response header** is provided. For development, run UI and backend through a same-origin proxy; do not expose this unauthenticated backend on a public interface.

| Endpoint | Request | Response |
| --- | --- | --- |
| `GET /health` | — | `{status:"ok",service:"parser-pair-backend",version:"0.1"}` |
| `GET /api/v1/parser-pairs/schema` | — | JSON Schema for all guided form controls |
| `GET /api/v1/parser-pairs/capabilities` | — | Schema-aligned authoring subset, import limits, feature flags and unverified target gates |
| `POST /api/v1/parser-pairs/validate` | Complete `ParserProject` JSON | `{ok,issues:[{code,path,message}]}` and HTTP 422 on invalid |
| `POST /api/v1/parser-pairs/generate` | Complete `ParserProject` JSON | `{contract, files:[{name,content,sha256,bytes}],manifest}` or HTTP 422 |
| `POST /api/v1/parser-pairs/inspect` | `{name,confContent,fragmentContent}` | SHA-256, sanitized diagnostic codes, opaque/read-only status; never raw source code in response |

**Capability negotiation:** Use GET /api/v1/parser-pairs/capabilities to gate UI controls. The six extraction formats are a **reviewed, bounded subset** of each format, not every variant of CEF, LEEF, CSV or RFC5424. HTTP receiver, multiple distinct source ports, multiline events and arbitrary Ruby authoring are NOT supported; legacy configurations remain inspection-only. The pinned nativeSyntheticProfile identifies a **synthetic test runner**, not a particular parser, live listener, proprietary wrapper, target import, or release readiness.

**Usage contract:**

1. UI constructs the typed project draft using field selection/mapping/receiver controls; it does not send arbitrary executable Ruby.
2. Call `/validate` to show exact schema/collision issues before the Generate button can proceed.
3. Call `/generate` only on a valid draft. UI downloads both returned files and may offer a ZIP constructed *locally*, without incorrectly appending `.rb` to the extensionless file.
4. Show the backend `manifest.status` (**DRAFT**) and warnings; the UI must not label the output verified or installed.
5. **No raw log samples** are part of the R1.5 model/API. A later private fixture/preview API needs a separate security and persistence contract.

Example payload is in [examples/synthetic-firewall.json](examples/synthetic-firewall.json) and includes documentation-only synthetic RFC5737 IPs. All paths and filenames are derived strictly from validated model fields; the HTTP API never accepts arbitrary filesystem paths.

## Persistence and security boundary

The server is stateless, bounded to 256 KiB generation JSON and 2 MiB **read-only inspection** input, and bound to loopback by default; not remotely published and has no authentication or tenant isolation yet. It does not execute Ruby or manage files. Generated Ruby embeds model JSON as Base64 to prevent source-code injection; only a reviewed fixed template is emitted. The runtime runner must be separate, pinned, isolated and privilege-limited before it processes untrusted customer records or before this is made multi-user.

**Integration note:** The docs/no-code-custom-parser-design PR #2 sets the future six-step UX and full generator requirements. Do not merge this backend without reconciling its API contract with the UI PR #3, which may independently advance.
