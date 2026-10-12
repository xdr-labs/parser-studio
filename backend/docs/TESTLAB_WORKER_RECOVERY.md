# Test Lab worker recovery: offline, fail-closed metadata

The existing synthetic session controller is an in-memory sender. The
new optional TestLabWorkerJournal can be configured by a trusted
in-network backend to record metadata only. This does NOT turn the default
backend into a durable, autonomous sensor-sending service.

## What can be recovered

A private hash-linked append-only JSONL journal records only:

- Random run ID and authenticated actor ID
- Reviewed artifact revision SHA-256
- FINITE lease expiry and replay mode/number of selected samples
- Session status and last acknowledged local delivery count

It deliberately never serializes log source, expected record, API Key, JWT,
sensor IP or selected UDP/TCP destination. The directory must exist with
owner-only permissions 0700 and the ledger is stored as an owner-only
0600 file named run-journal.ndjson; hardlinks, symlinks and insecure
parent directories are rejected. Writes append one canonical, hashed record
and fsync the file. Hash linking catches accidental file corruption; it is
not a signed append-only audit against the OS file owner.

The current code verifies all record transitions on load and rejects
duplicate/unsafe event keys, invalid owner, out-of-order sent counters,
incorrect SHA and closed-to-running resurrection. A missing/unsafe file or
exhausted on-host ledger capacity fails closed. This is a single-writer
offline design; distributed multi-host coordination and authenticated
cross-worker quorum are NOT implemented.

## Restart semantics

No session resumes automatically after a crash. On restart, the operator
may call journal.reconcile() to get only:

- REAPPROVAL_REQUIRED for a run whose lease has not yet expired
- EXPIRED_NO_RESTART for an expired run

Both report autoResumeAllowed=false, originalSourceRestored=false and
sensorIngestVerified=false. A permitted operator can create a NEW
session only after reentering/reapproving a sanitized source, artifact
revision, sensor destination, rate, tenant and network policy. It must not
reuse a stale auth grant, run ID or socket connection.

Optional in-memory SyntheticSessionController accepts recordTransition
from the trusted backend and an artifactRevisionId matching the reviewed
ZIP. If injected, metadata-only START must reach the ledger before the
first delivered event. Pause, resume, renewal, delivery counters and
terminal stop all produce metadata. If metadata persistence fails, no
new sending begins and any already active session is stopped or failed
closed. Shutdown cancels all active sessions.

The default createBackendServer() and server.ts do NOT inject a journal,
network sink, secrets or approval policy. Real sensor send and indexed
Interflow correlation require owner authorization and a separately
qualified in-network agent.

## Offline rate update and concurrent delivery safety

The in-memory controller can change a mock replay rate only with a separate
backend approval through approveRateChange. The allowed 0.2 to 5 events/s
range cannot extend its finite lease or event quota. A change is denied for
another actor, an unresolved delivery, concurrent requests, a terminal run,
or original-gap replay. The next pending timer is rescheduled after approval.

If Pause occurs while an asynchronous mock delivery is unresolved, the
session becomes FAILED with TESTLAB_SEND_OUTCOME_UNCERTAIN. The cancellation
signal is aborted, and Resume cannot replay that sequence. This is a
conservative acknowledgement rule, not proof that a network packet was or
was not delivered. The rate-change HTTP route is opt-in only; no live
sensor sender is enabled.

## Redacted per-stage evidence ledger (P0-LIVE-4, offline contract)

The optional TestLabEvidenceLedger is an in-memory metadata contract.
It can now be injected into SyntheticSessionController and retrieved via
GET /api/v1/test-lab/sessions/evidence?runId=... only when both the
controller and its authenticated per-session identity resolver are injected.
No default listener, live sensor integration, or customer-data access is
enabled. Opt-in Start requires a trusted actor and reviewed artifact SHA-256,
and each bounded synthetic delivery records its sequence without raw bytes.
The owned JSON response is a redacted report; unknown actors receive the
same NOT_FOUND response as a nonexistent run.

For each event, it distinguishes local GENERATED, SEND_ATTEMPTED and
SINK_ACCEPTED from independently observed SENSOR_OBSERVED and DP_INDEXED.
The latter two are only accepted with a strongly scoped receipt and a
separately injected backend observer. DP field comparison stores only
field names and MATCH/MISMATCH/MISSING states, never compared values.
No local callback, fake observer or report proves a real DP runtime.
Every report retains liveE2eVerified=false and runtimeParsingVerified=false.

Finite retention defaults to 64 runs, 500 events/run and 15 minutes.
With evidence enabled, Start and renewal enforce the 500-event ceiling.
Stopping an unresolved mock delivery records SEND_OUTCOME_UNCERTAIN,
never sensor acceptance or a successful send.
Actor and artifact identities, strict stage ordering, error-code allowlists
and bounded redacted reports are enforced. A restart loses all status and
cannot replay, reauthorize or prove prior delivery.

## Authenticated bounded rate-change HTTP (P0-LIVE-3)

The existing authenticated session HTTP handler now accepts
POST /api/v1/test-lab/sessions/rate only if an in-memory
SyntheticSessionController and server-side authorizeTestLabSession identity
callback are injected. The request contains exactly runId, approvalId and
ratePerSecond (0.2..5). Its owner authorization is identical to existing
Pause/Resume/Stop routes. A separate approveRateChange callback must grant
each change or the API rejects it. A rate change never extends the finite
session lease or increases event quota; original-gap scenario rates cannot
be rescaled. No default HTTP server, private credential profile or sensor
sink is initialized by this endpoint. Real sensor verification remains false.
