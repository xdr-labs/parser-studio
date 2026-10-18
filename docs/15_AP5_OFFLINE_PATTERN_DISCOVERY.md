# P1-AP5 — Privacy-preserving local pattern discovery

## Implemented UI scope

The beginner **Add Logs** step provides two optional, opt-in tools. They never change the current draft, open network connections, persist source data, execute scripts, or mark a parser native-compatible:

1. **Find Reviewed Pattern Hints** compares the exact full-sample browser suite with the family and consistently present field paths of fixed PUBLIC SYNTHETIC starter formats only. It returns up to three bounded structural hints, each visibly `REVIEW_TEMPLATE_ONLY`. All fields in a suggested template must be consistently present across original events to count in coverage. Known templates are *references*, not vendor parser bodies or transferable authorization.
2. **Group Unknown Text Locally** sends only the current bounded browser-session sample to an isolated, short-lived Web Worker. It examines only truly unrecognized text, not malformed structured messages. It groups up to 500 records into at most 12 structural class signatures with no user strings or raw values. A 1.8-second timeout terminates the Worker; partial/invalid inputs produce fixed status codes, not leaked data. Fixed classes include IP/URL/email/UUID/time/number/word, with a small public keyword allowlist. No Regex or Ruby is emitted.

Only the source line numbers, counts, reviewed public format labels, and sanitized token-class skeletons are displayed. Both tools are optional; novice Add Logs → Review Results → Test & Generate remains unchanged.

## Limitations and native boundary

The local token-class grouper is **not Drain3** and does not claim statistically qualified template mining, semantic field extraction, parser generation, or native Fluentd equivalence. A production-grade Drain3 worker would require a separate reviewed Python/process sandbox with CPU/RAM/time quotas, explicitly installed MIT license notices, held-out precision benchmarks, and owner-reviewed privacy boundaries. That backend component is not substituted by these browser hints.

P0-AP4 whole-event and holdout regressions remain mandatory before any suggested field mapping can be user-approved. Actual target DP/sensor/Interflow and frozen-head Full User E2E are independently gated.

## Tests

`knownParserFingerprints.test.ts` and `localPatternMining.test.ts` check public-only hints, all-event coverage, missing field confidence, rejection of mixed/unknown/forged suites, strict limits, bounded clusters, and absence of raw customer strings in returned reports. TypeScript/Vite build verifies the isolated Worker bundle.

## Optional real Drain3 0.9.11 — separately authorized backend

The existing browser-only structural grouping above remains a deliberately limited fallback. The private backend now has an actual, one-shot MIT-licensed Drain3 0.9.11 miner and an independent training/holdout evaluator, with Python CPU/memory/time/file/network restrictions, SHA-pinned dependencies, no persistence and fixed token-class redaction. It is **disabled by default** and requires trusted interpreter provisioning and separate backend authorization. GET /api/v1/parser-pairs/patterns/drain3/capabilities is a data-free authorization probe. Only after this returns an exact reviewed capability does the UI expose its separate, unchecked consent to submit the current raw sample and optional holdout to the **same-origin private backend**. No raw data is sent merely by opening the panel or checking availability.

The optional results identify only sanitized shapes, counts and training line numbers, never raw values, credentials or a runnable parser. The server has no general persistence or third-party/LLM connection. This genuine Drain3 worker does **not** automatically promote an inferred template to Stellar-native mapping. Backend implementation/test/provenance: backend/docs/drain3-offline-worker.md, backend PR #4 at 5ae5e88d171d8bbb0e6640e0301c01f5e3befa74. UI strict data-free capabilities/consent tests: src/guided/drain3OfflineClient.test.ts and tests/private-drain3.spec.ts. This is not a user/DP/sensor E2E.
