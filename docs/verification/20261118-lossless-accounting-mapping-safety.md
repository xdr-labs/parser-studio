# Lossless accounting and Map Fields safety — 2026-11-18

Candidate: isolated `experiment/codex-accuracy-lab-20261117`, after `b79ccea`.
This record describes local browser-preview evidence only. Added test strings
are authored synthetic/adversarial inputs, not vendor-derived compatibility
evidence.

## Implemented

- `src/guided/losslessAccounting.ts` independently accounts original UTF-8
  SHA-256 and bytes, per-event identity/hash/bytes, all-event count and parse
  status counts, structural leaves excluding raw-retention fields, browser
  normalized paths/count, exact supplied residual spans, and unmappable
  array/null/unsafe/ambiguous/depth-limited values. It bounds detailed output
  to 400 events and each path list, reports overflow/unaccounted identities,
  and leaves the overall proof `UNKNOWN` when parse, residual or output
  evidence is absent. Browser output is labeled as a preview, never native
  verification.
- Map Fields now shows exact Multi-Pass residual text and UTF-8 byte ranges
  only when the selected event's raw text exactly matches a current-sample
  Multi-Pass event. Missing or unmatched evidence is visibly
  `UNKNOWN / UNVERIFIED`. The repair button returns to the existing Review
  Fields flow. Native output remains explicitly unverified.
- An individually clicked official suggestion now preserves a mapping whose
  provenance is not `AUTO`, consistent with the existing bulk and ChatGPT
  import guards.
- Chromium scenarios cover partial-source repair navigation and explicit
  manual vendor mapping after FULL JSON extraction.

## Local checks

- Focused Vitest accounting, mapping UI, mapping suggestion, and privacy-safe
  ChatGPT prompt/import checks: **48/48 passed**. A later affected-file rerun
  after exact event alignment: **20/20 passed**.
- `npm test`: **237 test files passed; 2,062 passed / 1 failed**. The only
  failure is `src/guided/pythonTestSender.test.ts` attempting
  `spawnSync python3`, rejected by the sandbox with `EPERM`. Parent-provided
  host-runner evidence on baseline `b79ccea` is Python **191/191** and TS oracle
  **6,288/6,288**; that evidence does not qualify these later source changes.
- `npx tsc --noEmit`: passed after fixing the new regression test import.
- `npm run build`: passed. Vite emitted its existing large-chunk advisory.
- Chromium attempt:

  ```sh
  PARSER_STUDIO_TEST_MULTIPASS=1 npx playwright test tests/auto-parser-three-step.spec.ts --grep "partial source shows exact Multi-Pass residual|FULL JSON extraction still permits an explicit safe manual vendor mapping" --project=chromium
  ```

  Playwright could not start the local Multi-Pass HTTP server because the
  sandbox rejected its localhost socket with `PermissionError: [Errno 1]
  Operation not permitted`. A second run without Multi-Pass was also unable to
  start the configured web server. Chromium behavior therefore remains
  unverified here; run the command above on the permitted host runner.

## Still unverified / incomplete

- LF-0 broad independent grammar/source-value census and LF-1 complete browser
  E2E acceptance remain open. The added deterministic fixture strings are
  synthetic; they make no vendor-compatibility claim.
- MAP-1/MAP-2 full Chromium journeys and latest exact-head E2E remain open,
  despite existing focused mapping, privacy, stale-fingerprint, collision,
  and precedence tests.
- Native Ruby 2.4.9 / Fluentd parity has no runner in this checkout and remains
  **UNVERIFIED**. Actual Stellar Cyber 7.0 target import remains
  **UNVERIFIED**.
- No template approval hashes, external repository, branch, preview, target,
  or release state was changed.
