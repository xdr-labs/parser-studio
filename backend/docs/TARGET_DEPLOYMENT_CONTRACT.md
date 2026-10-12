# User-provided DP Apply readiness (offline; not activated)

**Owner P0-LIVE-0/1/2:** Generate produces one immutable revision. Download
and Apply must be independent. Download already works without credentials;
a real user-target HTTPS/API Key integration remains owner/environment-gated.
This module implements the locally testable artifact/approval/port/readback
coordination, not a production-verified target deploy.

## Backend-only contract

The TypeScript module backend/src/target-deployment.ts exports
TargetDeploymentCoordinator, validateDpTarget and validateTargetArtifact.
It is separate from POC-only LegacyPocClient: do not weaken that class's
loopback/null-sink protection.

There is NO default network transport and NO enabled real-target Apply route. The optional mock-only HTTP route is disabled in the standard CLI server.
A trusted backend operator injects an exact origin allowlist, tenant,
a TargetDeploymentApi, an independent per-write approve callback and a
durable audit callback. No key is imported from an existing dev-atlas
secret store or checked into this repository, URL, browser state, manifest,
stdout or a log.

Before each POST, the coordinator:

1. Recompiles the submitted PairExport and verifies it is byte-identical to
   the downloaded deterministic ZIP/manifest with expected revision ID,
   matching two file SHA-256 digests, port, version and metadata.
2. Checks that the HTTPS origin matches the backend-provisioned allowlist,
   with no URL userinfo, query, fragment, path or implicit localhost target.
   A future real transport MUST independently verify TLS certificates,
   DNS resolution/pinning and egress policy before each network request.
3. Uses the SAME destination/CONF source port for the sensor ingest
   and generated parser listener. The trusted injected TargetReference
   supplies sensorIngestPort, and mismatch with manifest.selectedParserPort
   fails BEFORE any target inventory GET or parser write;
   RFC5424 Syslog parser listeners below 6800 are invalid.
   An unverified port recommendation cannot enable Apply. The selected
   common port changes both generated artifacts and their revision hash.
4. Requires explicit confirmation of name, tenant, origin and approval ID,
   plus independent trusted backend approval. A UI checkbox is insufficient.
5. Looks up actual parser list, built-in/custom port catalogue and
   separately trusted sensor bindings and authoring reservations. Missing
   completeness evidence, name conflicts and occupied ports fail closed.
   Rechecks inventory just before write, and uses an in-process
   origin+tenant+name lock. Remote port allocation remains non-atomic.
6. Writes a metadata-only BEFORE audit record, submits the unchanged files
   to its trusted injected backend API without automatic retry, and
   verifies a unique matching name/version/port by GET readback.
   Unknown status or no readback is UNCERTAIN. Never auto-delete
   a general user parser after uncertainty.
7. Returns API_REGISTERED_READBACK separately from targetImportVerified,
   sensorReadyVerified and realRuntimeParsingVerified, all false.

Offline tests use only synthetic in-memory responses. No external DP,
POC or sensor was contacted.

## Test environment input — manual secure profile

The owner can now enter DP HTTPS URL, Tenant/User Scope API Key, Sensor IP,
ingest port/protocol and optional parser listener port using the operator
interactive script backend/scripts/configure-target.py. See
[TARGET_CONNECTION_SETUP.md](TARGET_CONNECTION_SETUP.md). It writes only
to a private owner-only profile outside the Git worktree at
~/.parser-studio-secrets/connection.json, never imports preexisting secrets,
and does NOT make API calls, reserve a port, or authorize deployment.

## Read-only connection inventory preflight

An owner-invoked read-only verifier is provided at
backend/scripts/verify-target-readonly.py. Its default mode is offline.
When the operator explicitly supplies --execute, it reads only the
private on-host test DP profile and performs exactly one User Scope JWT
exchange POST and two tenant-scoped Custom Parser inventory GET requests.
See TARGET_CONNECTION_SETUP.md.

This CLI does not authorize any writes and does not activate the backend
target adapter. The owner has now provided redacted JWT HTTP 200 and two
HTTP 200 inventory GET results (Custom 4 rows; Catalogue 441 rows).
Optional --suggest-port and --check-port inspect the same two GET responses
without an additional network request. The resulting listener proposal
NEVER authorizes deployment or proves sensor binding availability,
target port reservation or a working Fluentd runtime normalizer.

## Environment and owner gates (deferred)

An actual per-target connection requires a securely authenticated operator
session, independently confirmed tenant and DP ownership, short-lived
private API Key/JWT handling, verified TLS and DNS/IP-pinned transport,
sensor/listener and port relay inventory, separate per-target approval,
durable audit storage and direct reachable network access. A user-provided
URL is NOT an authorization to open an arbitrary fetch route. General PUT,
DELETE and restore require app-ownership provenance and separate approvals
that are not established by the POC-only reference.

The real deployment/Full User E2E can happen only with an owner-approved
test target. The offline coordinator is NOT a claim of real Stellar runtime
or proprietary parser compatibility.

## Mock-only user-target Apply service (P0-LIVE-2 partial)

The standalone TargetApplyMockGateway now implements a server-injected
mock-only Apply boundary. The test-only `POST /api/v1/parser-pairs/target/apply` and
`GET /api/v1/parser-pairs/target/apply/status?artifactRevisionId=...`
are available only when a trusted server explicitly injects
`targetApplyMockGateway`. `createBackendServer()` without injection
returns `TARGET_APPLY_DISABLED` and never creates a target client.
The mock route enforces independent backend actor authentication, strict
2 KiB JSON metadata-only requests, owned immutable revision selection,
per-write approval and audit, separate inventory recheck and unique fake
GET readback. The default CLI has no general target Apply enabled.

The trusted backend must inject a verified actor and tenant resolver,
a server-owned immutable revision lookup, independent operation approval,
an audit sink and an in-memory fake TargetDeploymentCoordinator. Its origin
MUST end in the non-routable .invalid domain. The browser may only submit
the revision digest, expected parser name/version, approval ID and explicit
confirmation; target URLs, API Keys, tenant identifiers, file bytes and
raw log content are never accepted as Apply inputs.

A mock attempt reuses the coordinator's exact Ruby/CONF hash checks, common
sensor/listener port constraint, collision inventories, last-second recheck,
auditing, one POST and unique name/version/port GET reconciliation.
The mock response is explicitly MOCK_READBACK_VERIFIED, not a real target
compatibility result. Unknown readback remains UNVERIFIED, with no retry or
delete. Status is scoped to the authenticated actor and revision, bounded
to 128 metadata entries with 15-minute expiry, and ephemeral across restart.

Real DP access still requires an entirely separate approved backend adapter,
durable artifact and audit stores, verified TLS/DNS/egress, tenant authorization,
real target readback, and per-write authorization. Neither the owner private
profile nor a live sensor is used by this test-only gateway.

## Offline revision history, hash diff and downloadable restore preview

The separate ArtifactRevisionHistory provides an in-memory owner+tenant
history of exact generated Ruby/CONF packages. Every inserted package is
recompiled and verified by buildArtifactPackage, then defensively copied.
The immutable revision SHA-256 is scoped to its owner and tenant: different
owners can independently store identical artifact digests. The register,
list, diff, download and prepareRestore methods require a trusted caller
identity; no browser-provided identity or self-asserted ownership is trusted.

Diff is limited to exact manifest hashes, version and the one shared sensor
and CONF listener port. It never includes private parser bodies or raw logs.
Owned ZIP downloads are reverified and copied before being returned. A
restore preview requires both owned revisions and the exact latest stored
revision as a concurrency check. It returns the old ZIP for offline review
and explicitly does NOT change history, perform a PUT/DELETE, modify
target state, or assert runtime parser support.

This test-only contract is not enabled in the default CLI and is not
integrated with any database. An explicitly injected
ArtifactRevisionHistory and independent authorizeArtifactRevision callback
enable only these authenticated offline routes:
POST /api/v1/parser-pairs/revisions/register,
GET /api/v1/parser-pairs/revisions/list?projectId=...,
GET /api/v1/parser-pairs/revisions/download?artifactRevisionId=...,
POST /api/v1/parser-pairs/revisions/diff and
POST /api/v1/parser-pairs/revisions/restore-preview.
Every route checks the server-resolved owner/tenant, and all archive
downloads have no-store headers. Offline restore-preview returns the
previous owner-owned ZIP without mutating target state or recorded history.
Storage is capped at 128 revisions and 24 hours, then lost on expiry
or process restart; this is not a persistent audit or disaster-recovery
backup. Production restore still
requires an approved durable storage and provenance design, separate
target authorization and actual readback verification.
