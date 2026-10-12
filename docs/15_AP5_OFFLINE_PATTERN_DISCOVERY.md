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
