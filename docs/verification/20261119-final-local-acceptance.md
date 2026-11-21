# Parser Studio — FINAL ISOLATED LOCAL ACCEPTANCE (2026-11-19)

## Decision: LOCAL IMPLEMENTATION COMPLETE; NATIVE/TARGET RELEASE GATES OPEN

Verified exact product-and-test code HEAD: `1db18cdbffc66c5990188317cb5cdd87c132b64f`.
Isolated branch `experiment/codex-accuracy-lab-20261117`.
Git remote push intentionally disabled. No PR, merge, main, preview, production, credentials, or managed DP alteration.

The owner-directed local task was bounded to source accounting, map UI correctness and regression proof.
New LF-0 matrix contains 12 authored/vendor-derived examples with independently asserted field values,
UTF-8 raw byte counts, SHA256 input fingerprints, event counts when known, parser status observations,
array/null/dotted/deep/1025-path and duplicate/malformed controls. Previous 24 vendor-derived fixture
census remains in the existing test suite. The new matrix is NOT a live device-captured original corpus,
not a universal parser proof, and does not supply actual native residual receipts.
The deterministic output is `src/guided/__snapshots__/losslessAcceptanceMatrix.test.ts.snap`.

### Same HEAD host execution evidence

| Gate | Observed result | Host log under /home/aella/.local/state/parserstudio-codex-lab-20261117/ |
| --- | --- | --- |
| Full frontend Vitest | **241 files, 2076/2076 PASS** | `20261119-final-exact-full-vitest.log` |
| TypeScript typecheck | **PASS** | `20261119-closure-typecheck-fixed.log` |
| Python suite | **191/191 PASS** on identical product code (before test-only TS narrowing) | `20261119-closure-python.log` |
| Grammar generator consistency | **PASS** on identical product code | `GRAMMAR_GENERATED_IN_SYNC` and `TS2RB_VERIFY` host output |
| TypeScript semantic oracle | **6288/6288 PASS**, primary mutants 32/32 killed, on identical product code | `20261119-closure-semantic.log` |
| Frontend build | **PASS**, existing bundle-size warning | `20261119-final-exact-frontend-build.log` |
| Backend build | **PASS**, canonical semantic policy matched | `20261119-final-exact-backend-build.log` |
| Real Chromium novice, partial/unknown, mixed, manual+AI/JSONata | **9/9 PASS** | `20261119-final-chromium-novice.log` |
| Real Chromium same-head authoring backend + DRAFT Ruby/CONF and ECS JSONata | **2/2 PASS** | `20261119-final-chromium-backend.log` |
| Worktree | **clean** | `git status --short --branch` |

The final code difference after the full initial Python/oracle run was exclusively a test
TypeScript discriminated-union access correction, separately typechecked and directly tested.
Frontend full Vitest, frontend/backend builds and all 11 Chromium paths passed at final HEAD.

### Verified local functionality

- Raw source SHA256, UTF-8 byte count, ordered event accounting, original/residual evidence and browser
  output are separate; missing independent evidence is UNKNOWN, never promoted to complete structural parsing.
- Original field leaf names remain visible; full canonical paths preserve identity. Arrays/null/unsafe
  paths and unmapped or omitted source values have explicit dispositions, not phantom native emission.
- Auto suggestions, privacy-reviewed optional ChatGPT JSONata, and manual field selection preserve
  manually approved mappings; conflicts/type issues and stale proposals fail closed.
- Partial/unknown input cannot bypass the authoring gate. User can review original source and residuals.
- Actual backend generated Ruby/.conf DRAFT artifacts through an exact-HEAD authoring API in Chromium.
  This validates authoring; it does NOT prove the generated Ruby executes correctly on Stellar Cyber.

### OPEN gates — not local development blockers and not waived

1. **Native Ruby 2.4.9 + Fluentd output field/value parity UNVERIFIED:** no Ruby executable in
   the isolated dev-drlink account; Docker installed but server API access denied
   (`permission denied ... /var/run/docker.sock`). No permission bypass or image installation attempted.
2. **Full backend suite requiring native Ruby/optional Drain3 NOT QUALIFIED** in this environment.
   Backend build and actual authoring API E2E passed, but are not substitutes for native runtime tests.
3. **Real captured vendor-original logs plus independent end-to-end extracted-source/true native-emitted
   value census NOT FULLY QUALIFIED.** Existing fixture provenance is labeled vendor-derived or authored.
4. **Actual Stellar Cyber 7.0 DP parser import, UDP/TCP ingestion, indexed event/value parity
   UNVERIFIED**; requires separately authorized target environment and release acceptance procedure.
5. No main merge or preview rollout was approved or attempted.

These are external/native/target acceptance gates. Do not reopen or extend LOCAL feature development
without a concrete supported defect; local source candidate is frozen for acceptance review.
