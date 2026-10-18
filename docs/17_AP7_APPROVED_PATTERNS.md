# P1-AP7 — Explicitly approved browser-local mapping library

## Implemented

- Existing P0-AP4 can compare one deterministic candidate against every original source record and a separately provided, independent holdout. Any regression, missing event, removed/retyped normalized field, forged browser suite or omitted holdout keeps **Approve Reviewed Mapping** unavailable.
- Explicit approval modifies the current browser draft only. A separate **Also save approved mapping names/types** checkbox is off by default. Only when deliberately checked at approval will the application store up to 20 allowlisted mapping signatures with source/target path, type, group, format, positive counts and holdout denominator in browser-local storage. No raw samples, field values, native claim, API keys or sensor data are included.
- A reused saved mapping remains **a candidate**, not an auto-applied patch: the operator must select the record, compare it against the current full source and a new independent holdout, review the before/after report and click Approve again. Duplicate/conflicting targets, family mismatch, unsupported target compiler and unsafe paths fail closed. The parser receiver/port and other accepted rules are retained.
- Saved browser-local signatures can be individually forgotten only by selecting an entry and confirming the removal; current live parser rules and other saved revisions are untouched.
- The UI exposes per-session counts of compared proposals, approved proposals and regression blocks. These are diagnostic session counters, **not** a formal before/after human usability evaluation or published task-time improvement. No telemetry or persistent metrics are sent.

## Boundaries

This is neither a silent self-improving AI parser nor a real Stellar native regression. An actual sampled-user measurement, provider-driven repair, target DP/sensor Interflow and full release/E2E remain separately gated. The backend Draft PR #4 owns the native compound compiler and has not been modified by this UI lane.

## Tests

`approvedPatterns.test.ts` validates an exact user-approved mapping contract, independent holdout requirement, rejection of forged/unsafe storage entries, absence of raw event data and explicit reuse preserving original drafts. The preexisting `autoParserRegression.test.ts` covers full-event/holdout comparison and rejected regression patches.
