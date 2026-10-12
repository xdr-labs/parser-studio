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
