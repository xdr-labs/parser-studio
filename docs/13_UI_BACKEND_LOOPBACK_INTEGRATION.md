# P0-AP1 — UI ↔ Backend Loopback Integration Candidate

**Scope:** offline, public synthetic fixtures, nonproduction, no PR merge.

The UI and parser-pair backend remain in **separate Git branches and worktrees**.
This candidate runs the real Node HTTP server and the real Chromium UI as
**two independent localhost processes**, connected through a fixed same-origin
Vite development proxy. It does not copy the backend source into PR #7 or
merge its PR #4. No live DP configuration, tenant credential, sensor destination
or customer sample is accepted by the integration harness.

## Exact trusted inputs

- UI branch: `feat/r2-guided-backend-api-bridge`, Draft PR #7. Record the actual
  checked-out HEAD in test evidence.
- Backend branch: `feat/r15-parser-pair-backend`, Draft PR #4, pinned SHA
  `5a0a58881296bb10ca3a381acba267ac63b50763`.
- Backend qualification: CI
  [#38247886313](https://github.com/xdr-labs/parser-studio/actions/runs/38247886313)
  passed Node/API 281, Python 36 and pinned Fluentd synthetic 10 profiles /
  23 golden cases on this exact backend SHA. **This does not prove any
  user-generated parser's native execution or Stellar target compatibility.**

The UI quality workflow checks out **only `backend/`** from the reviewed SHA,
installs/builds it separately, verifies its Git HEAD, and runs a dedicated
Chromium suite against its actual loopback service. Existing browser-mock tests
remain independent; a mocked response cannot satisfy the integration gate.

## Run locally (isolated dev-atlas)

Ensure the pinned backend checkout is clean, built and contains
`backend/dist/src/server.js`. The test harness starts the backend as a child
on loopback `127.0.0.1:4191` and Vite on `127.0.0.1:5180`. They both stop
after Playwright completes. Never point the proxy to a real DP.

```bash
cd /home/aella/parser-studio-guided-backend-bridge
PARSER_STUDIO_LIVE_BACKEND=1 \
PARSER_STUDIO_BACKEND_ROOT=/home/aella/parser-studio-backend/backend \
PARSER_STUDIO_BACKEND_HEAD=5a0a58881296bb10ca3a381acba267ac63b50763 \
PARSER_STUDIO_BACKEND_PORT=4191 \
npx playwright test tests/integrated-backend.spec.ts --project=chromium --workers=1
```

The backend SHA must exactly match before any browser starts. CI runs the
same code with a separately pinned sparse checkout. The two processes bind
**loopback only**; no public reverse proxy or target listener is enabled by
this test. Public-synthetic samples remain client-side until explicit
authoring actions submit a typed `ParserProject` metadata model.

## Required real HTTP/browser proof

1. Real GET `/schema`, GET `/capabilities`: validated reviewed v0.1
   contract with newer owner-gated offline revision and synthetic manifest
   capability fields. An available endpoint does not authorize its use.
2. Real guided browser preview → typed `ParserProject` → POST `/validate`
   → POST `/generate`: both requests must carry the **same** sanitized
   typed project with no raw log records, credentials or sensor addresses.
3. Real generation must produce the matching extensionless Ruby and CONF
   filenames with two SHA-256-verified file bodies, a DRAFT manifest and
   receiver/CONF port alignment. Real POST `/package` must return the same
   verified immutable ZIP and listener port; subsequent POST `/inspect`
   must reproduce the exact original generator pair without executing Ruby.
4. Default 403 for native capability manifest, offline owner revisions,
   MOCK_ONLY Apply, Test Lab evidence and unrelated-owner data; reject
   invalid projects, MIME violations and tampered real generated responses.
   A source edit must invalidate all previous draft-generation evidence.
5. Chromium tests are authoritative for browser user interaction. Browser
   pass does **not** prove native parser equivalence for a customer record,
   actual Stellar loader import, DP writes, sensor receipt or Interflow.

These same-origin development endpoints must never grant automatic access
because they were reachable. Authenticated offline revision/Test Lab/manifest
operations are **disabled by default** until independently authorized server
components are injected. No production or release action is performed.
