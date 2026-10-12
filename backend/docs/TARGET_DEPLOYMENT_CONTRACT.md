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

There is NO default network transport and NO public HTTP Apply route.
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
3. Requires explicit confirmation of name, tenant, origin and approval ID,
   plus independent trusted backend approval. A UI checkbox is insufficient.
4. Looks up actual parser list, built-in/custom port catalogue and
   separately trusted sensor bindings and authoring reservations. Missing
   completeness evidence, name conflicts and occupied ports fail closed.
   Rechecks inventory just before write, and uses an in-process
   origin+tenant+name lock. Remote port allocation remains non-atomic.
5. Writes a metadata-only BEFORE audit record, submits the unchanged files
   to its trusted injected backend API without automatic retry, and
   verifies a unique matching name/version/port by GET readback.
   Unknown status or no readback is UNCERTAIN. Never auto-delete
   a general user parser after uncertainty.
6. Returns API_REGISTERED_READBACK separately from targetImportVerified,
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
target adapter. A successful inventory response alone cannot guarantee
sensor/listener port availability, indexed Interflow data, or normalizer
runtime operation. The externally approved POC read check must be
recorded separately from synthetic/mock tests.

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
