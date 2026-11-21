# Lossless-first isolated host qualification — 2026-11-18

## Identity and boundaries

- Verified CODE HEAD: `aac57970f1e7afda5eef20b1e4abb12fb85c3137`.
- Branch: `experiment/codex-accuracy-lab-20261117` in the isolated dev-drlink local clone.
- GitHub main baseline: `af7de35f3bfdefa14f283b409959c37e73eea53c`.
- Git push disabled. No push, PR, merge, preview, production or Stellar Cyber DP7 import.
- These checks qualify locally executable candidate behavior, **not** native runtime or DP7 behavior.

## Independent host results (same CODE HEAD)

| Gate | Result | Evidence under /home/aella/.local/state/parserstudio-codex-lab-20261117/ |
| --- | --- | --- |
| Full frontend Vitest | **238 files; 2,063/2,063 PASS** | `20261118-final-full-vitest.log` |
| Python unittest | **191/191 PASS** | `20261118-final-python.log` |
| TypeScript check | **PASS** | `20261118-final-typecheck.log` |
| Frontend production build | **PASS** (preexisting Vite chunk advisory) | `20261118-final-build.log` |
| Backend production build | **PASS** | `20261118-final-backend-build.log` |
| Grammar + TS→Ruby generator consistency | **PASS** (core, generic, probes) | `GRAMMAR_GENERATED_IN_SYNC`, `TS2RB_VERIFY` in same-head run |
| TS semantic oracle | **6,288/6,288 PASS**, 32/32 primary mutants killed | `20261118-final-semantic.log` |
| Real Chromium novice Auto Parser | **7/7 PASS** | `20261118-host-all-chromium.log` |
| Real Chromium exact-head backend DRAFT Ruby/.conf | **1/1 PASS**, generated DRAFT artifacts | `20261118-host-integrated-draft.log` |
| Local Git tree | **clean** | `git status --short --branch` |

The browser journey verified field extraction vs raw preservation, three-column
mapping, automatic vendor-leaf passthrough, a deliberate human target change
without losing original values in the browser preview, privacy/safety gates,
unknown event residual text and generation lock, and a DRAFT Ruby/conf download
from the same-head authoring backend.

## Critical distinctions

- Raw-source retention, proven structured extraction, and normalized browser
  output presence are **different**. The accounting module never calls a raw
  copy a parsed leaf. Missing structural/residual evidence is UNKNOWN.
- `PRESENT_BROWSER_PREVIEW` does NOT prove the generated Ruby actually emits the
  same record or that a Stellar Cyber sensor can import it.
- Normalized/vendor field retention in the Chromium preview was observed. This
  does not replace a native Fluentd output record-by-record comparison.
- Test inputs include independently authored and vendor-grammar-derived fixtures.
  None of these are claimed to be a captured original vendor corpus.

## Remaining acceptance and external verification

1. **Native Ruby 2.4.9/Fluentd parity UNVERIFIED:** no Ruby runtime available
   and Docker daemon not accessible to the isolated developer account.
   Generated-template sync and build PASS do not replace runtime execution.
2. **Real Stellar Cyber 7.0 DP import/receive/indexing UNVERIFIED:** outside
   the isolated authorized experiment, requires a separately approved target.
3. **Broad captured vendor source/value census NOT FULLY QUALIFIED:** sample
   coverage spans authored security grammar and adversarial fixtures, but not
   a captured original production vendor matrix with source-to-native emitted
   field/value oracle for every record.
4. **End-to-end optional ChatGPT response import in the browser NOT FULLY
   QUALIFIED:** the privacy-reviewed manual copy/paste, fingerprint rejection,
   semantic review and precedence have unit coverage; the whole novice AI
   response import journey was not one of these browser acceptance scenarios.
5. **Full backend runtime suite NOT QUALIFIED on this host:** build passes, but
   native Ruby and optional Drain3-dependent tests cannot pass here.
   No claim of full backend test PASS.

This is an implementation+host-test receipt, not a release authorization.
