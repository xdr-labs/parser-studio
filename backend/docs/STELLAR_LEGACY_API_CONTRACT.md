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

## General user-target readiness (owner/environment gated)

A separate general-target backend coordinator in target-deployment.ts
validates exact downloaded ZIP/PairExport revision and port hashes, uses a
trusted DP HTTPS origin/tenant allowlist, requires real sensor port evidence,
independently approved writes and redacted durable audit with GET readback.
It does not have a default transport or HTTP endpoint, so it cannot yet
apply to arbitrary user DPs. See TARGET_DEPLOYMENT_CONTRACT.md.

## P0-LIVE-0 — Independent download (no DP URL or API Key)

After /api/v1/parser-pairs/generate returns its DRAFT PairExport, the user
can always download the original two files separately using returned files[]
contents, without configuring any Stellar DP. For a combined archive POST
/api/v1/parser-pairs/package with exactly a pair containing the unchanged
PairExport and version 1.0.0.
The response is a binary ZIP with extensionless Ruby, matching .conf and
manifest.json, and stable revision/SHA-256 headers. It validates names,
byte lengths, hashes, manifest and exact reproduccibility; it never rewrites
the compiled Ruby/CONF or calls a vendor API.

The manifest declares selectedParserPort, receiverProtocols, projectRevision,
version, artifactRevisionId, both file byte counts/hashes and all verification
flags false. Port/rule edits must re-run Generate: a selected port change
changes BOTH file hashes and artifactRevisionId. ZIP is deterministic.
Download never reads DP URL/Key, requires no tenant/login and cannot
invoke parser registration.

Apply to Stellar is a separate explicitly confirmed operation. It requires
additional target-ownership checks and matching artifact-revision hashes
before POST/PUT. Only guarded POC test deployment is currently enabled
and user-target Apply is not yet ready; Download remains independent.

## P0-LIVE-3 initial: format-aware synthetic preview, NO network sender

The backend provides a pure in-memory JSON/unquoted-KV preview generator
in testlab-synthetic.ts and an explicitly authenticated local POST
/api/v1/test-lab/preview. The request selects raw sample, deterministic seed,
sequence, optional timestamp field, selected IPv4/username/URL field paths,
and optional existing run-marker field. Timestamp is updated to current
server time while preserving an explicit Z/offset and fractional precision
for the supported RFC3339 string subset. Safe documentation-only IPv4,
synthetic usernames and synthetic.invalid URLs are generated via typed field
parsing, not global regex substitution. Unsupported grammars, paths, old
timestamps, and unsafe values fail closed without echoing raw logs in errors.

Server must inject authorizeTestLabPreview from the current user's trusted
identity; otherwise the route is 403. Preview responses expressly mark
safeToSendToSensor=false, runtimeParsingVerified=false and
targetSensorVerified=false. There is no UDP/TCP connection, continuous
worker, real sensor verification or customer data retention in this batch.
Only approved, sanitized source samples should be supplied to the preview.
CSV synthetic preview additionally accepts explicit ParserProject-matching
csvColumns (ordered array) and csvDelimiter (comma, semicolon or TAB).
It rejects mismatched column count, duplicate/unsafe column names, physical
newlines and invalid quote escaping; otherwise serializes CSV values using
double-quote escaping, preserving column positions and parseability.
Any timestamp column is updated only if explicitly selected. CSV is covered
by both Node contract tests and the pinned native sample_csv parser callback.
Standalone CEF version 0 and LEEF 1.0/2.0 have separate, bounded
field-aware replay support. They preserve original raw header and carefully
parse extension fields before changing any value. The CEF extension follows
the strict unquoted KV subset. LEEF 2.0 supports approved single-byte,
including 0xHH, delimiters with unsafe whitespace/newline/NUL/equals
variants rejected. Malformed escaped delimiters, duplicate/unknown fields,
unsupported versions and physical multiline fail closed. Native tests use
the matching generated standalone CEF and LEEF Parser Plugin profiles.
The RFC5424 v1 preview additionally supports exactly NILVALUE Structured
Data (-) with an explicit KV body. The header PRI/host/app/process/msgid
is retained and the RFC3339 header clock is automatically regenerated.
Variables use parsed nested body.field paths; the optional timestampField
can identify syslog_timestamp or an existing body timestamp field.
Adjacent Structured Data elements, Syslog-embedded CEF/LEEF and multiline
are NOT Test Lab preview-supported yet.

Other log families remain unsupported for Test Lab preview until qualified.

Other log family emitters await their own synthetic/native qualification.

The clean offline native qualification separately emits seven reviewed
synthetic JSON/KV/CSV/CEF/LEEF/RFC5424 previews (both LEEF 1.0 and 2.0)
from fixed public-synthetic fixtures and runs all seven through pinned
Fluentd Parser Plugin API. It verifies
mapped srcip, unchanged action, classification and one callback per event.
The ignored exact-HEAD report records offlineSyntheticPreviewNativeChecked=true,
offlineSyntheticPreviewCases=7 and sensorTrafficSent=false.
This is not an actual in-network sensor sender.

## P0-LIVE-3 session control — server-only trusted sink

The backend implements a bounded in-memory SyntheticSessionController with
Start, Status, Pause, Resume and Stop, backed only by a trusted injected
approval callback and delivery sink. It has no default transport or sensor
destination, so ordinary server startup CANNOT transmit logs. Session state
tracks a server-generated run ID, next sequence, last delivery time, counts,
lease deadline and static errors; status never returns the original raw log.
Stopping the session cancels timers without changing or deleting any parser.

With an injected controller and a trusted per-request product identity
callback, the HTTP paths are POST /api/v1/test-lab/sessions/start,
POST .../pause, POST .../resume, POST .../stop,
POST .../renew, and GET .../status?runId=.... The identity callback MUST return a stable
authenticated actor ID from the server's existing identity provider,
never an unverified browser-provided header. The controller binds each
run to its authenticated owner and masks foreign and unknown run IDs as
the same 404 error. Owner identity is not returned to the browser.
Start needs selected bounded sample/schema, explicit approval reference,
rate 0.2..5 events/s, a finite 250ms..15min lease and a max 3000 event cap.
Stop, expiry and delivery failure release source from retained session memory.
The async delivery path serializes attempts and never automatically retries
a failed send. Every delivery callback receives an AbortSignal; a future
trusted sensor sink MUST honor cancellation. Stop suppresses future ticks but
cannot retract an already-sent packet. Concurrent approval requests reserve
capacity before awaiting the external authorization, closing the backend
server cancels/purges all sessions, and late approval cannot restart a
closed controller. The in-memory loop is NOT durable across server
restart. An optional secure metadata-only journal can report
REAPPROVAL_REQUIRED or EXPIRED_NO_RESTART after restart, but never
automatically resumes network packets or restores raw source. See
[worker recovery](TESTLAB_WORKER_RECOVERY.md).
With a separate trusted approveRenewal
callback, a verified session owner can POST /renew with runId, approvalId,
leaseMs and additionalEvents. Each renewal independently validates owner,
operator approval, remaining lease, 250ms..15min new lease, 0..3000 extra
events and a bounded total 300000 events. Concurrent or late renewal is
rejected; STOP, EXPIRE and SHUTDOWN always win. The session can continue
while the owner keeps explicitly renewing finite leases, rather than
gaining an uncontrolled infinite network sender.
Pause/Stop never modify or delete the deployed parser.
Any real in-network UDP/TCP adapter additionally needs target ownership,
egress protection and direct sensor authorization before enabling product UI.

All HTTP session routes return TESTLAB_SENDER_DISABLED (403) unless both the
trusted controller and per-user/session authorization are injected. A
successful synthetic callback or nonzero sentCount means only that the
injected sink accepted a synthetic event, not that any real sensor ingested
it or Stellar indexed and parsed the expected fields. This implementation
has no UDP/TCP agent configured by default; actual customer sensor
traffic sent remains zero. An opt-in server-side sink module has been added
and validated only with local ephemeral loopback UDP/TCP test receivers.
The static capabilities continue to mark liveSensorSenderEnabled=false.

## P0-LIVE-3 curated multi-event replay scenario (offline qualified)

The bounded pure backend scenario planner accepts two to twelve sanitized,
individually format-aware synthetic samples, each with a fixed ID and an
existing run-marker field. The user chooses one of two deterministic
schedules: constant-rate cycles round-robin through all samples using
the separately approved events-per-second ceiling, while original-gaps
uses explicit relative millisecond offsets plus a finite cycle period
to retain the reviewed event spacing pattern. Every interval must be at
least the rate-limit interval, and a review cycle is at most 15 seconds,
with no gap longer than three seconds. Invalid rates, duplicated sample
IDs, malformed formats/markers and unsupported source content fail closed
without echoing source strings.

The separately authenticated POST /api/v1/test-lab/scenario/preview
takes a scenario, zero-based sequence and approved max ratePerSecond. It
returns one selected sample event, nextDelayMs, family ID and honest
unverified flags using an obviously synthetic placeholder run marker.
It does not allocate a live session or open any socket. UI can preview
all selections before requesting an independent Start approval.

Existing POST /api/v1/test-lab/sessions/start remains backward-compatible:
a caller supplies EITHER one sample or one scenario, never both. The server
evaluates all entries against the supported synthetic extractor first,
then injects its generated run ID, uses one authenticated session owner
and approval, and routes only through a separately configured trusted sink.
Status adds replayMode and sampleFamilyCount, not any raw sample.
Stop/expiry/server shutdown cancels the entire scenario and purges the
retained source text from each family. A lease remains finite, requiring
independent operator-approved renewal. No automatic DP upload occurs.

This is a user-reviewed gap schedule, NOT automatically derived timing
from arbitrary private event logs, and is NOT real sensor delivery proof.
Native Fluentd crosschecks still cover the individual format variants.
Recorded-gaps and scenario features are backend-only until UI PR #7
integrates the documented schema.

## P0-LIVE-4 Interflow search/correlation — MOCK contract, no POC data access

A separate User Scope read client now composes the documented
GET /connect/api/data/{index}/_search request with Stellar Lucene q,
size, track_total_hits=false and strict tenantid, bounded UTC millisecond
timestamp range, explicit generated run marker and one known normalized
index (session, threat, syslog or winlogevent). The query is bounded to
100 results and a 15-minute time window. It reuses the server-held JWT;
only GET may refresh/retry once on HTTP 401. HTTP 403 or unsupported
response structures never count as verified parser success.

POST /api/v1/test-lab/interflow/search is available only when the backend
operator injects the authorized Legacy POC client, an in-memory Test Lab
controller, a separate tenant data-read principal callback AND a mandatory
private audit sink. The supplied runId is checked against the session owner;
no raw log search is permitted from just the parser CRUD authorization.
The server validates every expected field name and its scalar value before
requesting upstream data, but logs only field names/tenant/run/time in audit.
The response contains MATCHED_RESPONSE_FIELDS, FIELD_MISMATCH, or NO_MATCH
plus field-level MATCH/MISMATCH/MISSING; it contains NO raw vendor document,
API Key, JWT or actual field value. A matched mock or API response alone
never sets sensorReceivedVerified or endToEndVerified true.

Only the independently inspected xdr-labs/stellar-data-exporter User Scope
request shape has been reused. The current user's User Scope key has NOT
been checked for actual Interflow search permission, and there has been
no live DP Interflow lookup. The UI must label this UNVERIFIED for the
real target until an owner-approved in-network E2E proves otherwise.
Bounded polling is available via
POST /api/v1/test-lab/interflow/poll using the same exact seven search
fields as /search plus maxAttempts (1..6) and intervalMs (250..3000),
with total bounded attempt window no greater than 15 seconds.
Polling stops at the first complete field match, otherwise returns
NO_MATCH or FIELD_MISMATCH without claiming sensor receipt.
Permission checks, run-owner verification and metadata-only audit
repeat BEFORE every single upstream GET; access revocation, upstream
403/401 failure or malformed response aborts polling with no automatic
retry. If the browser connection closes, the backoff sleep is cancelled.
The response includes attempts and explicitly unverified cursor and
search-permission flags. This is request-bound bounded polling, NOT an
unbounded background job. The vendor cursor API has not been evidenced
or implemented.

Actual indexed event proof and full end-to-end normalized field proof
remain separately owner-gated and unverified.

## P0-LIVE-3 opt-in UDP/TCP transport — local loopback evidence only

The module backend/src/testlab-transport.ts exports createApprovedSensorSink,
which can be injected as the session controller's trusted delivery function.
It requires an exact numeric IP literal, selected ingest port/protocol
(UDP or TCP), a backend-owned allowlist with an exact matching target, a
trusted authorization callback evaluated before each packet and a
separate mandatory pre/post audit sink. The destination is never taken from
a Test Lab HTTP request. No DNS names are accepted, avoiding DNS rebinding
and implicit SSRF to attacker-selected hosts. A safe operational egress
controller and direct target ownership authorization are still required
for an actual customer sensor.

The current bounded sender writes a raw datagram for UDP and appends
one newline frame for TCP. The initial JSON/simple-KV subset includes
a run marker which must match the authorized run ID. It enforces a 16 KiB
event limit, no physical multi-line or NUL values, per-attempt timeout,
AbortSignal cancellation, no automatic retransmit and metadata-only audit
without raw logs, API keys or tokens. On delivery failure the session
fails closed. The injected sink MUST be owned by the trusted in-network
backend, not the browser. Audit success proves only local kernel socket
acceptance, not sensor ingestion or actual Interflow indexing.

Synthetic tests create ephemeral UDP/TCP receivers on 127.0.0.1 only,
including Start to multiple UDP raw events to Stop, independent TCP
framing and a policy revocation mid-session. No real sensor, DP, POC
or production destination was contacted. Exact-HEAD native qualification
records syntheticLoopbackUdpTcpNodeTestsPassed=true alongside
sensorTrafficSent=false and targetImportVerified=false.

Current backend/src/server.ts does NOT wire this transport in; default
product liveSensorSenderEnabled=false. External in-network delivery and
real matching Interflow results remain gated by owner-approved target
policy, credentials, sensor reachable network and full User E2E.

## P0-LIVE-1 — Port proposal (NOT atomic or a live sensor check)

The backend-only stellar-port-plan.ts module merges trusted lists of known
occupied parser-listener ports from the tenant Custom Parser listing, built-in
parser catalogue, independently evidenced sensor parser bindings, local
authoring-session reservations, and administrator-reserved ports. Its default
editable candidate range is 20000..30000. It skips known collisions and
rejects manual overrides on an occupied or privileged port.

The returned status is CANDIDATE_REQUIRES_DEPLOY_RECHECK if all four inventory
completeness flags were verified, or INCOMPLETE_EVIDENCE otherwise; neither
status is a deployment approval. Every result sets deployableNow=false,
candidateOnly=true and needsFinalRecheck=true. Never accept inventory
completeness fields from an untrusted browser or assume a catalog GET is
an atomic reservation. Sensor *ingest destination* ports are separate from
internal parser listener ports. Do not infer a sensor mapping from the
suggested parser port.

Authorized UI callers may query GET /api/v1/stellar/legacy/port-proposal
and optionally supply ?port=NNNNN for a user override. It reads both known
POC/tenant inventory endpoints but, without independently injected active
sensor binding data and local reservations, always returns
INCOMPLETE_EVIDENCE and deployableNow=false. UI must not describe this
as confirmed port availability. Only the backend operator can inject
portPlanningContext inventory and configurable recommended range.

A future target-specific service must resolve and recheck sensor bindings,
permissions and port reservations before separately approved upload, then
regenerate Ruby+CONF+manifest for the selected port and invalidate the old
artifact revision.

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

## Independent local native guard for disposable test configuration

The clean exact-HEAD native qualification now emits a fixed, publicly
synthetic disposable pair through stellar-disposable-smoke.ts (nothing
uploaded or persisted). The reviewed TypeScript pair/manifest and template
guard must pass before its CONF is streamed to the pinned Fluentd 1.17.1
configuration parser. The AST check enforces two UDP/TCP sources, localhost
bind, reserved test port, exact parser name and a single null sink with
no external includes. The evidence report records
pocDisposableLoopbackNullSinkAstChecked=true and
pocApiMutationPerformed=false. This is **not** an installed POC loader or
live listener test.

## Verification status

TypeScript API tests use synthetic in-memory fake transport and never
repeat real POC CRUD; exact-HEAD Ruby 3.2.3 and Fluentd 1.17.1 offline
native qualification continues to validate the parser fragment separately.
Real POC HTTP integration, actual sensor parsing, full UI user E2E and
release all require their own owner-controlled gates.

No merge, deploy, credential relocation or production change is authorized.
