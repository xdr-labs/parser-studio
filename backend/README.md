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

The pinned Fluentd Parser API suite additionally checks 23 **independently authored public synthetic golden events** across the ten generated profiles against full expected normalized records, including event timestamps and sanitised failure paths. The committed fixture set is under test_native/fixtures; no real customer/vendor raw log is committed. Separate ignored synthetic-import and synthetic-golden reports include exact source hashes. Successful synthetic replay is **not** a real target loader or customer raw-log E2E.

The suite writes `.tmp/synthetic-native-report.json` with SHA-256 provenance and explicit `targetImportVerified:false`. It exercises Fluentd's real Parser Plugin API and config syntax but **does not** install a plugin, open a live listener, or validate Stellar Cyber imports. See [native qualification](docs/NATIVE_QUALIFICATION.md) and [CI permissions](docs/CI_SETUP.md).

## Web UI contract

See [complete API contract](docs/API_CONTRACT.md) for all form fields, additional log formats, supported enrichment operations, input limits, errors, and honest export readiness.

All API input/output is strictly UTF-8 JSON, with invalid UTF-8 and unpaired JSON Unicode escapes rejected rather than silently replaced; only application/json and an optional charset=utf-8 are accepted. **No CORS response header** is provided. For development, run UI and backend through a same-origin proxy; do not expose this unauthenticated backend on a public interface.

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


**Stellar Cyber Legacy POC API adapter:** See [backend/UI API integration contract](docs/STELLAR_LEGACY_API_CONTRACT.md) for server-only User Scope JWT, strict paired-file manifest validation, readback/version checks, explicit test-only write approval and static unverified Modular/runtime gates. General writes remain disabled.


P0-LIVE-0 independent ZIP download: POST /api/v1/parser-pairs/package takes
the same exact PairExport plus version and returns a reproducible ZIP with
extensionless Ruby, .conf and manifest.json, including listener port,
immutable artifact revision and SHA-256. It works with no DP URL/API Key;
generation and downloading never auto-deploy.
See docs/STELLAR_LEGACY_API_CONTRACT.md.


P0-LIVE-3 offline synthetic preview: POST /api/v1/test-lab/preview is
server-authorization gated and generates deterministic JSON/unquoted KV
synthetic events with current RFC3339 timestamp and documentation IP,
username and URL variants. It does not open network connections or claim
actual sensor delivery/parsing; see docs/STELLAR_LEGACY_API_CONTRACT.md.


P0-LIVE-3 sender lifecycle primitive: SyntheticSessionController provides
bounded in-memory Start/Pause/Resume/Stop, a run ID, five-events/s ceiling,
lease expiry, sequential backpressure and sanitized status. All session
HTTP routes require separately injected trusted backend approval, authenticated
server-side actor identity, and delivery sink. Sessions are actor-bound,
concurrency-limited and cancelled/purged when the backend HTTP listener
closes. A separately reapproved /sessions/renew extends the bounded
lease and per-session event quota, without resetting Stop semantics.
Stop signals cancellation to the sink. The default app has no sink
and performs no sensor traffic; sessions do not survive server restart,
and no real sensor/Interflow parsing result is claimed.


P0-LIVE-3 optional sensor transport (NOT ENABLED): server-only
createApprovedSensorSink supports bounded UDP (raw datagrams) and TCP
(newline framing) with exact numeric-IP/port/protocol allowlist, per-event
trusted approval, metadata-only audit, abort and no retries. The standard
server entrypoint does not configure this module. Synthetic local 127.0.0.1
receivers are tested; NO live sensor/POC/production traffic, Interflow
indexing or parser-runtime success is claimed. See
docs/STELLAR_LEGACY_API_CONTRACT.md.


P0-LIVE-4 Interflow read-only correlation (MOCKED CONTRACT):
POST /api/v1/test-lab/interflow/search requires a separately authenticated
run owner, a server-held User Scope credential, explicit raw-data permission,
bounded tenant/time/index/run-marker filters and pre-query audit. It returns
only MATCH/MISMATCH/MISSING statuses, never raw vendor logs. The module was
tested with synthetic fake HTTP responses; real Interflow permission,
indexing, runtime field normalization and sensor receipt remain unverified.


P0-LIVE-4 bounded Interflow polling (MOCKED, no actual DP queries):
POST /api/v1/test-lab/interflow/poll uses the same tenant/run-marker/time
and field-diff contract as /search, adding maxAttempts and intervalMs with
a max 15-second bounded request. Per-attempt read permission, run ownership,
and audit are rechecked; results expose only MATCH/MISMATCH/MISSING, count,
attempts and false end-to-end/real target verification flags. No vendor
cursor, unbounded polling worker or production search permission is claimed.
