# Isolated lossless accounting increment — 2026-11-19

## Scope and identity

- Branch: `experiment/codex-accuracy-lab-20261117`
- Starting HEAD: `901927d3f8399418618773ebc709c62a3364e498`
- Work was performed in the isolated clone only. No push, PR, merge, release, target import, credential change, or template approval change was performed.
- Fixture provenance remains `AUTHORED_FROM_VENDOR_GRAMMAR` / vendor-grammar-derived where labeled. No captured original vendor sources were added or claimed.

## Implemented

- Lossless accounting now reconciles every supplied event's exact raw record, in order, to every nonempty source line. A missing, copied, reordered, or omitted record makes proof `UNKNOWN` and identifies the supplied event IDs as unaccounted.
- Residual spans must be positive integer UTF-8 byte ranges within the event raw bytes. Invalid spans and bounded/truncated path reports prevent `COMPLETE`.
- The mapping editor no longer prepends the artificial `parserstudio_source.` namespace to a source path shown to the author; the canonical path remains in mapping metadata and full source-tree review.
- Turning on `omitSourceRaw` now displays a prominent alert stating that the original line will not be emitted and only parsed/mapped fields remain.

## Exact local evidence

- RED before fix: `npx vitest run src/guided/losslessAccounting.test.ts` failed both added regressions (caller-reported FULL without full source reconciliation; invalid residual/path truncation still reported complete).
- GREEN focused: `npx vitest run src/guided/losslessAccounting.test.ts src/guided/NormalizationMappingReview.test.tsx src/guided/vendorHoldout20261116.test.ts src/guided/juniperSdNormalization20261104.test.ts src/guided/vendorFieldNames.test.ts` — 5 files, 61 tests passed.
- `npm run typecheck` — PASS.
- Full `npm test` — 237 files passed; 2066 tests passed, one test errored because spawning `python3` returned `EPERM` in the sandbox (`src/guided/pythonTestSender.test.ts`).
- `python3 -m unittest discover -s tests -p 'test_*.py'` — 191 tests run; 188 passed, three loopback server tests errored because opening a local socket returned `PermissionError: [Errno 1] Operation not permitted`.
- `git diff --check` — PASS.

## Open gates

- Exact broad adversarial accounting report across nested arrays/null/dotted or duplicate keys, depth and field caps, mixed CEF/LEEF/syslog/RFC3164/RFC5424, quoted CSV, incomplete/unknown records, and all holdouts is not yet produced. Existing holdout semantic tests are retained; they are not represented as a new independent runtime-emission proof.
- Browser Chromium and browser AI import journey were not run in this sandbox; loopback sockets are restricted.
- Ruby 2.4.9/Fluentd is unavailable; Docker daemon access is denied (`/var/run/docker.sock`). Native generated-Ruby parity remains UNVERIFIED.
- Stellar Cyber 7.0 import/indexing and captured original vendor source matrix remain UNVERIFIED / unavailable.

## Phase 2 — Auto Parser UI wiring and deterministic corpus

- The active Auto Parser Map Fields path now passes its exact `sample` string to `NormalizationMappingReview`; no new top-level mode was added. The review runs `accountLosslessSource` locally in an abort-guarded React effect. Multi-Pass residuals are attached by event index only when each event raw string matches at the same index and the arrays cover the full event set; missing evidence remains absent and yields UNKNOWN.
- The existing three-column Final event panel shows total UTF-8 source bytes, shortened SHA-256 with the full hash available to assistive technology, event count, per-event structural statuses and leaf counts, browser output leaves, residual evidence presence, and raw-copy output status. It explicitly says browser preview is NOT native Ruby / DP verification. UNKNOWN shows a warning and read-only raw sample. Record accounting completion is described as source reconciliation, never as full parsing. Existing `canGenerate` logic is unchanged.
- Added React component coverage for UTF-8 byte accounting, full event/index evidence, changed sample and mapping state, missing/short Multi-Pass arrays, raw sample visibility, arrays/null and leaf labels for source-port/destination-port. A separate deferred-accounting component test verifies stale asynchronous results are discarded after the sample changes.
- Added a deterministic corpus test over all 24 `tests/fixtures/vendor-holdout-20261116/*/raw.log` fixtures (explicitly vendor-derived, not live originals) plus authored UTF-8 JSON, null/array/dotted-key, CEF, LEEF, quoted CSV, KV, depth, 128-field, and mixed multi-event samples. It runs the existing browser `preview` and accounting oracle, asserts source byte count/hash shape, event count, exact structural status accounting, and that absent Multi-Pass residual receipts keep accounting UNKNOWN. It labels browser output separately from native Ruby / DP.
- Focused evidence: `npx vitest run src/guided/NormalizationMappingAccountingCancellation.test.tsx src/guided/NormalizationMappingReview.test.tsx src/guided/losslessAdversarialCorpus.test.ts src/guided/losslessAccounting.test.ts` — 4 files, 27 tests passed. `npm run typecheck` — PASS. `npm run build` — PASS (Vite reports the existing >500 kB bundle advisory). `git diff --check` — PASS.
- This does not close the independent FULL/PARTIAL/UNKNOWN field/value proof: the added corpus lacks a native Multi-Pass receipt, so its accounting proof correctly remains UNKNOWN. Native Ruby 2.4.9/Fluentd and real DP7 parity remain UNVERIFIED; Docker API access is still denied. Broad fixture output review, browser E2E, and real source-backed contracts remain open.
- Full frontend/Python suites are not recorded as PASS due to the runner errors above. Backend native suite and exact-head browser gates remain open.
