# Parser Studio backend — R1.5/R3 synthetic native parser qualification

**Ownership:** Backend only. Other session owns the Web UI in Draft PR #3. This branch deliberately changes only `backend/**` (the denied workflow lives only as a template under `backend/docs/`); it does not modify any UI, legacy docs, remote td-agent or production target.

## Supported, precisely

- Strict, version-neutral `ParserProject` 0.1 JSON Schema in [schema/parser-project.v0.1.schema.json](schema/parser-project.v0.1.schema.json).
- Supported subset: JSON, strict quoted KV, CSV, RFC5424 Syslog (optional JSON/KV/CEF/LEEF body), standalone CEF and LEEF. Typed top-level/nested/vendor field mapping supports `string`, `integer`, `ip`, `port`, `boolean` and ISO8601 timestamps requiring an explicit timezone.
- Ordered classification by `equals` or `exists` (including enriched output), default `syslog`, and generated `stellar_log_index`. Allowlisted no-code enrichments: `set_const`, `copy`, `lowercase`, `uppercase`, plus bounded exact-delimiter `split_field` and `merge_fields`. Split/merge never evaluate Regex or code and fail closed on missing fields or mismatched split counts. Typed field errors include stage and input field path without leaking log content.
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
server-authorization gated and generates deterministic JSON/unquoted KV,
strict single-line CSV, CEF 0, bounded LEEF 1.0/2.0 and RFC5424 v1
(NILVALUE SD, KV body) synthetic events with current RFC3339 timestamp
and documentation-only IP, username and URL variants. It does not open network connections or claim
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


Offline scenario inspection: POST /api/v1/test-lab/scenario/preview
(requires server-side preview authorization) takes a bounded scenario,
sequence and max rate and returns only one generated synthetic event and
safe scheduling metadata. It does NOT open a sender, create a live run,
reuse credentials or send customer data to any target.


Operator connection setup (offline only): Run
python3 backend/scripts/configure-target.py on a trusted interactive
dev-atlas SSH terminal to enter test DP HTTPS URL/Tenant/User Scope Key
and Modular Sensor IP/port/UDP-TCP; optional parser listener port.
The key uses hidden terminal input and is saved OUTSIDE the repository at
~/.parser-studio-secrets/connection.json, protected by 0700/0600 permissions.
--check verifies stored permissions without printing private values.
No automatic DP connection, synthetic sending, or deployment is enabled.
See [operator setup](docs/TARGET_CONNECTION_SETUP.md).


Test Lab operator worker recovery (opt-in, no live traffic): metadata-only
TestLabWorkerJournal records actor, artifact revision, lease, counts and
STOP/FAIL transitions to a private hash-linked append-only 0600 journal.
Any interrupted run requires reapproval; there is no automatic restoration
of source logs, network sockets or delivery, and the default server never
enables this journal. See
[worker recovery design](docs/TESTLAB_WORKER_RECOVERY.md).

Read-only operator DP check: python3 backend/scripts/verify-target-readonly.py
is OFFLINE by default; --execute in a trusted dev-atlas SSH terminal uses
the private on-host test profile for exactly one User Scope JWT exchange POST
and two tenant-scoped Custom Parser inventory GETs. It prints redacted
HTTP statuses/counts only, with redirects disabled and verified HTTPS.
There are no parser mutations, sensor packets or Interflow lookups.
Live verification is distinct from offline unit-test PASS. See
docs/TARGET_CONNECTION_SETUP.md.

The read-only verifier also accepts --execute --suggest-port or
--execute --check-port PORT. Using only the same permitted JWT exchange
and two GETs, it checks known Custom Parser/catalogue listener ports
and returns a provisional non-conflicting candidate or known collision.
This does not reserve a port, inspect live sensor bindings, store a
selected port or enable deployment. It outputs no customer parser names
or API Key.


Parser listener/Modular Sensor ingest port contract: both values MUST be
identical. A single port entered via configure-target.py is written for
both, and existing profiles with null preferred_listener_port inherit the
sensor port. RFC5424 Syslog parser CONF ports must be >=6800; the Syslog
port proposal starts at 6800 and avoids observed occupied ports.
The guarded sensor sink rejects a destination/CONF port mismatch.
Even a collision-free candidate never proves actual sensor/runtime
availability; the target must be rechecked before any approved upload.


## Optional offline durable artifact revision and mock Apply audit store

By default all revision APIs are disabled and no revision artifacts, log samples,
credentials, mock Apply audit or target state are persisted. A trusted backend
operator may explicitly inject DurableArtifactRevisionHistory instead of the
ephemeral ArtifactRevisionHistory into createBackendServer. This is a
single-writer, offline-only development adapter, not a production database.

Provision an existing private directory owned by the service user (mode 0700),
outside shared project trees and outside the private DP credential directory.
Pass its canonical absolute artifact-revisions.json path to the constructor.
The adapter never creates/relaxes directory permissions. It stores the approved
paired Ruby/CONF artifact contents under a private mode-0600 JSON snapshot.
Only actor/tenant/revision/time/phase/status metadata appears in the embedded
mock audit ledger; there are no sample log events, API keys, DP origins, sensor
addresses or approval tokens in audit entries. The /revisions/list response
returns persistent:true only for an explicitly injected durable adapter, and
/capabilities reflects that opt-in state.

Example of trusted server-side injection (not a browser route):

    const history = new DurableArtifactRevisionHistory(
      "/trusted/private/dir/artifact-revisions.json");
    // Supply independent server-side identity verification and a
    // .invalid-only mock coordinator; never trust browser-provided IDs.
    createBackendServer({
      artifactRevisionHistory: history,
      authorizeArtifactRevision: authenticateTrustedRevisionOwner,
      targetApplyMockGateway: new TargetApplyMockGateway({
        mode: "MOCK_ONLY",
        authorize: authenticateTrustedTargetActor,
        resolveRevision: async (a, id) => {
          try { return history.resolveOwnedRevision({ownerId:a.id,tenant:a.tenant},id); }
          catch { return null; }
        },
        getCoordinator: trustedMockCoordinatorOnly,
        audit: async event => { history.recordMockApplyAudit(event); },
      }),
    });

Every operation reopens the snapshot and revalidates the exact ZIP/pair SHA-256,
tenant/actor, checksum, version and file permissions. Atomic fsync+rename,
exclusive writer lock, TTL, maximum 256 metadata-only audit events and bounded
artifact capacity fail closed on corruption or unsafe paths. A stale lock or
broken ledger requires explicit operator reconciliation; never remove a lock
without verifying there is no active writer. Whole-file hashes detect accidental
corruption, not malicious modification by the authorized host/file owner.
The file contains parser artifact bodies, so never publish or commit it.
There is no default on-disk location, automatic server startup integration,
real DP write, sensor send or live target verification.


## Opt-in redacted Test Lab evidence file export

When a trusted server injects an authenticated SyntheticSessionController with
TestLabEvidenceLedger, the existing owner-scoped run evidence is available
through GET /api/v1/test-lab/sessions/evidence-export?runId=<test_run_id>.
This **read-only** download returns deterministic, bounded JSON as an attachment:
testlab-evidence-<test_run_id>.json. The x-parser-evidence-sha256 response
header lets the caller compare bytes against a locally calculated SHA-256;
it does not authenticate an untrusted server, prove independent provenance
or establish successful ingestion.
The exporter rechecks the strict evidence schema and stage/count consistency
before any bytes are returned. It rejects extra values, source logs, keys,
credentials and unproven runtime/DP/sensor success flags. Anonymous, cross-run
and cross-actor requests are rejected by existing server authentication and
run-owner checks; the default server leaves the route disabled.
No exported run survives the existing in-memory TTL unless an operator
independently saves the authorized download. No automatic sensor sending,
real DP interaction or extra persistent state is enabled.


## Opt-in Test Lab field coverage and grouped failure summary

GET /api/v1/test-lab/sessions/evidence-summary?runId=<test_run_id>
uses the same authenticated, owner-only and disabled-by-default session path
as the redacted evidence report. No new sensor, DP query or callback occurs.
The backend revalidates the exact evidence-report allowlist and recomputes
the counters, then exposes only field *names* with matched/mismatched/missing
counts, coverage percent across separately observed DP-indexed events, and
known send failure codes with grouped event counts. Field values, vendor
event content, credentials, proof receipts and origins are never returned.
If no authenticated independent DP observer verified any events, the comparison
status is NOT_VERIFIED and field coverage is empty. Even when offline/mocked
observer callbacks exist, the summary's realSensorVerified,
runtimeParsingVerified and liveE2eVerified flags are always false.
Reports are transient, subject to existing run TTL, and never constitute
a Stellar Cyber production E2E verdict.


## F13 pinned synthetic native regression comparison (offline only)

The fixed reviewer-authored PUBLIC SYNTHETIC golden runner records a
value-free per-event result (PASS/error class plus SHA-256 of the canonical
normalized output, not the raw or normalized record). Native qualification
still FAILS if any golden case fails. After an exact-HEAD successful offline
qualification, its reviewed per-case evidence is archived to the ignored,
owner-only backend/.tmp/native-regression directory using 0700/0600 modes
and a bounded 64-HEAD retention limit. Unsafe paths, overwrites and conflicts
fail closed, never delete a prior baseline automatically.

From the backend directory, compare two already qualified Git commits with:

    node dist/scripts/native-regression.js compare BASELINE_HEAD CANDIDATE_HEAD

Both arguments must be full 40-character Git commit IDs as returned by
git rev-parse HEAD, not the 64-character artifact or fixture SHA-256.
The comparison requires identical fixture SHA-256, the same pinned
Ruby 3.2 / Fluentd 1.17.1 engine, and identical case IDs/parser profiles.
Results include SHA-only output changes and redacted improvements,
regressions, other failure changes and unchanged counts. Malformed reports,
changed fixtures or spoofed vendor success claims are rejected.

Only FIXED PUBLIC SYNTHETIC fixtures are supported. There is no arbitrary
Ruby execution, no automatic target Apply, no raw log/credential persistence
and no actual Stellar Cyber loader, DP, sensor, Interflow or customer-data E2E
claim. SHA checks detect accidental corruption but do not attest to an
independently trusted or signed operator. Genuine owner-supplied fixtures
and vendor verification remain separately gated.
