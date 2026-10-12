# P0-AP4 — Browser-local whole-sample, holdout, and reviewed repair

## Scope and evidence boundary

`autoParserRegression.ts` implements a strict per-event source-identity and aggregate-consistency checker. It rejects truncated, reordered, stale, oversized or falsely verified browser suites. The entire original sample is accounted for, including malformed/unknown/RFC3164 events. Bounded fixed-code reasons and format family counts, positive coverage, additions/removals/type changes are reported without raw events, field values or diagnostic messages. This is **browser-only** evidence, never native Fluentd/DP/Interflow evidence.

## Explicit repair workflow

An advanced review section within **Test & Generate** proposes at most one new safe custom-field mapping using existing conservative deterministic field suggestions. No parser edits are applied automatically. The candidate replays the whole original sample and optionally independent holdout records in the isolated browser Worker. Only **Approve Reviewed Mapping** mutates the local draft, and only when a supplied independent holdout suite is valid, all original events are accounted for, prior passing results remain passing, and no field is removed or retyped. Candidate execution, previews and holdout are never sent to the backend or saved as raw logs. A source/draft/holdout change invalidates the comparison.

**Not implemented here:** unreviewed native compound compiler transforms, Drain3 worker, JSONata execution, real DP Apply, sensor send, or proprietary Interflow verification. Browser comparison is a separate gate and cannot advance those statuses.

## Tests

`src/guided/autoParserRegression.test.ts` covers source integrity, independent holdout, mixed/unknown/RFC3164 accounting, no-leak summary, refusal of forged native flags/aggregate counts, honest missing-holdout status, and explicit proposal/non-mutation. The main UI is checked by TypeScript/Vite build and the existing developer browser suite; complete human E2E and actual target testing are separately gated.
