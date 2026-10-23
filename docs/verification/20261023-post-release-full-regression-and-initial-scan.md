# 2026-10-23 — Post-release full regression, public corpus and initial-scan correction

## Exact scope and provenance

Owner requested complete regression and real Web E2E after the approved PR #146
merge and public development rollout. Baseline development Git tree is merged
`main=45017addd74ab06976e967cf4be4ea8ad0891947`, equivalent to qualified
PR #146 source `dbfa292c2f20312b49e20816d04b0c694d09e802`. The publicly
installed development app at `https://app.parser.xdr.ooo/` served
`/assets/index-ju3N30ev.js` during this baseline test. No production,
DP/sensor, target-import, mobile or external raw-log transmission was exercised.

## Full baseline regression evidence

- Frontend Vitest: **146 files / 1,135 PASS**, 0 failures.
  Log: `/tmp/parserstudio-regression-unit-20261023.log`.
- All 16 in-repo standard-library Python test modules:
  **100 PASS**. Log: `/tmp/parserstudio-python-all-20261023.log`.
- Offline authoring backend build/check PASS. Backend authoring regression:
  **463 PASS**, 0 failures, with previously installed isolated Ruby 3.2.3 in
  `/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin`.
  The first local attempt without that PATH was an environment-only
  `spawnSync ruby ENOENT` failure, **not** a passing run. Valid repeated
  run: `/tmp/parserstudio-backend-with-ruby-20261023.log`.
- Entire registered Chromium test collection: **356 cases in 75 files,
  330 PASS, 26 conditional SKIP, 0 unexpected, 0 flaky**. Run used exact
  source-root built backend, explicit browser-only service, independent
  in-repo Multi-Pass preview and no live target. JSON report:
  `/tmp/parserstudio-full-chromium-20261023.json`. Skips are primarily
  owner-gated historical real-backend/evidence/Test-Lab/sensor paths; they
  were never counted as successes or silently enabled.
- Live public HTTPS Chromium on 54 authored representative security log
  variants: **54/54 browser journeys PASS**, zero page errors/HTTP 5xx, all
  inputs retained. Of these **42/54 reached source-complete Review Fields**
  and **12/54 remained honest review-required paths**. Logs/reports:
  `/tmp/parserstudio-public-54-20261023.log` and
  `/tmp/parserstudio-public-54-20261023.json`.
  The review-only families included ModSecurity text, Cisco ASA, Juniper SRX,
  WatchGuard, Snort, Zeek with headers, DNS/proxy positional text, W3C headers,
  CSV quoted/invalid cases and unsupported Windows XML. This matrix is
  authored test syntax, **not** independently verified manufacturer output,
  target compatibility, accuracy percentage or parser-file qualification.

## Confirmed novice UX defect and correction

On the **actually installed** public development page, two valid positional
CSV rows produced the contradictory simultaneous messages **"0 events need
attention"** in the initial format scan and **"2 events need attention"** in the
full parser analysis. Similarly, a W3C sample with two header lines and two
data rows displayed four preliminary counted records versus two logical data
events without separating the statuses. No source values were lost.

The initial format scan now explicitly describes preliminary recognition,
including unrecognized source records, rather than asserting how many events
still need parser work. Once the user completes Analyze Logs, the adjacent
status explicitly directs the user to the authoritative full parser analysis.
When headers change the denominator, the two different counting units are
explained. Existing lexical invalid-CSV / duplicate JSON / duplicate KV
preflight guards remain unchanged. The Auto user flow and backend contracts
are unchanged.

New Playwright test:
`tests/novice-scan-vs-parser-status-20261023.spec.ts`.
Original baseline **RED 2/2**; changed candidate **GREEN 2/2**.
A source-pinned, built-backend + in-repo Multi-Pass focused regression of
eight affected spec files: **19/19 PASS, 0 skipped**.
Frontend Vite + TypeScript and offline backend check/build also PASS.

## Boundaries and acceptance

This initial-scan fix is a distinct development candidate and is not
installed on the public development server. The existing merged release
continues to serve the previously approved assets. The fix changes
presentation and matching lexical-census test expectations, not the
underlying grammar, source bytes, normalized fields or Stellar Cyber 7.0
dictionary. The overlapping historical Draft PR #145 was not merged or used
to restore removed Test Lab, sensor, source-export or expert tools.

The next gate is exact-head GitHub CI and explicit owner approval for any
subsequent merge or public development rollout.
