# Stellar Cyber Legacy Custom Parser API — backend/UI contract v0.1

**Evidence:** API verification session Draft PR #8, overlapping independent
PR #9, hardened reference PR #10 at e83f02d30e64b2a66f58df7a7d8e9202b15cdc16.
The owner-approved POC verified User Scope Key exchange, tenant-scoped GET
list/catalogue, and disposable Legacy paired-file create, version update,
readback, delete, and absence readback. There were no residual test parsers.
This does **not** verify proprietary runtime parsing, live sensor activation,
Modular JSON REST import, or enable/disable APIs.

## Runtime wiring and secret management

The server-only TypeScript modules are:

- stellar-legacy-plan.ts: pair size, name, SHA-256, manifest and tenant/port
  checks; deterministic disposable loopback/null-sink test pair construction;
  exact reviewed compiler-template SHA-256 and embedded synthetic IR gate.
- stellar-legacy-client.ts: POC-host restricted JWT authentication, eight-minute
  proactive token renewal, tenant-filtered read-only inventory/catalogue,
  explicit per-operation server approval and audit, multipart file writes,
  version/readback checks and guarded cleanup for one owned test identity.
- http.ts: optional server-side client injection, read authorization and
  default-disabled test-write routes.

The ordinary server entrypoint creates the backend **without a Legacy
client, credential, read grant or write gate**. It cannot make POC requests.
The owner's User Scope Key remains on **dev-atlas**; this implementation did
not retrieve, copy or assume that secret exists on dev-drlink. A future
approved BFF/operator service may inject a LegacyPocClient with a key obtained
from its own private secret manager, a read authorization callback, and
server-side durable approval/audit handlers. Do not send an API Key or JWT
to the browser, request body, Git, frontend environment files or audit logs.

An optional dedicated backend host can explicitly load a separate
operator-provisioned private JSON profile using loadPocProfileClient(path),
whose required fields are exactly host, tenant and key; this performs strict
owner/file/parent permissions and NOFOLLOW checks and returns only a client
with private credentials. The operator may supply createPocFileAuditSink(path)
for append-only owner-controlled 0600 NDJSON audit output. Both use explicit
backend-only absolute paths, never user-supplied HTTP paths. The audit
directory must already be owner-controlled 0700. The main server entrypoint
does **not** invoke these functions or read the user's existing dev-atlas
secret; they must be wired by the authorized BFF/operator application.

Important: an audit file alone does not establish operator approval.
The trusted backend must provide authorizeLegacyRead(request) for reads
and a separate approveWrite(intent) policy for each test write/cleanup.
The approval callback must check target, tenant, exact name, method,
version, expected version, file hashes, ticket and expiry; a mere UI
checkbox or arbitrary approvalId string is insufficient.

An HTTP client-supplied confirmed=true is **never** itself sufficient to
authorize a write. The backend must explicitly enable test writes AND supply
a real trusted approval callback plus an audit callback. Never use a
no-op audit callback outside synthetic automated tests.

## HTTP API (all on the existing private loopback backend)

| Method | Path | Behavior |
| --- | --- | --- |
| GET | /api/v1/stellar/legacy/capabilities | Static evidence and current configured/write-gate flags; no upstream call |
| GET | /api/v1/stellar/legacy/parsers | Tenant-scoped redacted list of name, version, optional port (server read grant required) |
| GET | /api/v1/stellar/legacy/catalogue | Tenant-scoped port and optional parser name only (server read grant required) |
| POST | /api/v1/stellar/legacy/prepare | Pure local two-file manifest validation; returns safe hashes, names, port and test-only eligibility, NEVER deploys |
| POST | /api/v1/stellar/legacy/create | POC test identity only, with confirmation, server approval/audit, preflight, POST and GET readback |
| POST | /api/v1/stellar/legacy/update | Same guards, expected-version check, PUT multipart and GET version readback |
| POST | /api/v1/stellar/legacy/delete | Same guards, exact test-only identity, expected-version check, DELETE and GET absence readback |

Preparation input: {"pair": <backend PairExport from /generate>,
"tenant": "<selected tenant>", "version": "1.0.0"}.
The tenant for actual authenticated calls comes from the server-side
credential configuration, **not** the supplied UI input. In a configured
client, any supplied tenant must match that selected backend tenant.

Test writes additionally include confirmed:true and approvalId referencing
a separately approved backend-side grant. Update must supply expectedVersion;
delete supplies name, expectedVersion, confirmed, approvalId, and optionally
tenant. Both files are posted as repeated multipart/form-data field "file":

- customized_<slug> (no extension) — Ruby parser fragment
- customized_<slug>.conf — matching Fluentd config

POST form fields: cust_id, parser_name, version and both file parts.
PUT: cust_id, version and both file parts, with parser name in URL.
DELETE: cust_id query parameter and the exact parser name in URL.
Access-token endpoint: POST /connect/api/v1/access_token with
Authorization: Bearer <server-held User Scope Key>; other API calls use the
server-held JWT. GET may refresh/retry ONCE after 401. No automatic
POST/PUT/DELETE retries after a timeout, 401, or other uncertain result.

## Rejected general uploads and runtime truthfulness

Normal Parser Studio /generate returns a DRAFT customized Ruby and CONF
using production-shaped transport/routing directives. These can be
validated locally by /prepare but **cannot** pass the disposable POC writer.

The separate makeDisposablePocTestPair helper returns an explicit
synthetic-fixture test project with:

- name customized_ps_api_crud_test_<6-16 hex> and port 7800..7999;
- one or two UDP/TCP source blocks, all with bind 127.0.0.1;
- matching source tag and parser name; one matching @type null sink;
- no external @include, filters, public binds, rewrite_tag_filter or extra
  configuration blocks;
- Ruby matching the SHA-256 pinned reviewed compiler templates from PR #10,
  with only the Base64 synthetic project IR changing; schema, projectId,
  vendor, slug, port, bind and protocols cross-checked against CONF;
- exact per-file bytes, individual SHA-256, and matching manifest hashes.

Legacy upload may immediately become active. There is NO general parser
auto-deployment route, no Modular REST upload or activation route, no
production entitlement, and no claim that API acceptance means runtime
parsing succeeded. Upload results separate:

- apiRegistrationVerified: true only after GET readback or absence check
- runtimeParsingVerified: always false until separate real-event/engine gate
- targetImportVerified: false for this generated draft contract
- modularActivationVerified: false (unsupported/unverified API)

For an ambiguous write, do not retry the write automatically. For an
acknowledged new test-parser POST with unverified readback, a separate
server-authorized CLEANUP may issue at most one DELETE for that exact
owned disposable name and recheck absence; otherwise mark unresolved for
operator reconciliation. Never delete unrelated tenant parsers.

## UI PR #7 consumption handoff

1. Fetch /capabilities. Keep Modular upload/activation controls disabled
   and display Legacy POC evidence separately from engine/runtime readiness.
2. After browser-side /validate and /generate, verify the two generated
   names/lengths/SHA-256, then call /legacy/prepare with the DRAFT pair.
   Never auto-deploy on generation or show a green deployment badge.
3. Call authenticated /legacy/parsers and /catalogue only through the
   server's authorized same-origin BFF. Show per-tenant names, versions
   and reserved/occupied ports, with no credentials in the browser.
4. Show guarded Legacy create/update/delete only in an operator-approved
   nonproduction test workflow; require explicit confirmation and a
   backend-authorized approval reference. Normal general-pair controls
   remain disabled. Show mismatched versions, name/port conflicts, upstream
   permission errors, and uncertain outcomes as distinct states.
5. A write succeeds only when apiRegistrationVerified=true after GET.
   Never relabel it as runtimeParsingVerified, sensor activation or
   production-ready. Manual target/real-log verification is separate.

All JSON responses use Cache-Control:no-store, nosniff and strictly
UTF-8 input. Error responses contain static codes and, for upstream failures,
HTTP status and method only; never raw source, upstream error body, key,
JWT or customer log data. Common codes include:
LEGACY_NOT_CONFIGURED (503), LEGACY_READ_DENIED (403),
LEGACY_WRITES_DISABLED (403), POC_NAME_CONFLICT (409),
POC_PORT_CONFLICT (409), POC_VERSION_CONFLICT (409),
POC_CREATE_UNVERIFIED (409), POC_FILE_INTEGRITY (422),
POC_RUBY_UNREVIEWED (422), POC_CONF_UNSAFE (422),
LEGACY_UPSTREAM_HTTP (502 with method/status).
The backend's unverified capability flags must remain false.

## Verification status

TypeScript API tests use synthetic in-memory fake transport and never
repeat real POC CRUD; exact-HEAD Ruby 3.2.3 and Fluentd 1.17.1 offline
native qualification continues to validate the parser fragment separately.
Real POC HTTP integration, actual sensor parsing, full UI user E2E and
release all require their own owner-controlled gates.

No merge, deploy, credential relocation or production change is authorized.
