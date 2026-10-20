# Full browser history — restore without unnecessary duplicate checkpoints

**Date:** 2026-10-20 KST
**Base:** Draft PR #116, `0021de3313392f70fbae1728bcfd46b8bf25715b`.
**Scope:** LOCAL-1/LOCAL-2 user-owned, origin-scoped browser snapshots; isolated development only.

## Independently reproduced user-visible defect

In a clean Chromium browser profile, create 30 valid snapshots through the actual UI. The current working copy is exactly the last saved version, V30. Choose Restore on V1 and accept the confirmation. The original implementation attempts to save an unnecessary 31st copy before restoring and fails at the existing 30-record capacity. Chromium observed V30 retained where V1 was requested, with the local history-full status. This baseline is a failing regression, not a passing user journey.

This differs from PR #116: all 30 records in this case are valid. Removing rejected records cannot resolve it, and automatically discarding any saved version would violate the preservation contract.

## Implementation

`saveLocalVersion` retains ordinary explicit-save behavior, including distinct named snapshots and unchanged count/byte limits. The new `saveLocalRestoreCheckpoint` reuses that storage path, allowing a verified identical snapshot to serve as the pre-restore safety copy **only when the bounded history is full**. Below capacity, the normal new Before restore checkpoint is still created.

A reusable record must pass the existing complete shape and SHA-256 verifier and exactly match the requested working copy's source, dataset name, draft/settings/mappings and optional named log groups. Similar text, a matching display label, or the UI's cached list is not proof. Verification occurs outside the write transaction; inside a single read/write transaction the entire candidate row must still equal the verified content. A changed, missing or corrupt candidate cannot be reused. Ordinary save and restore failures remain fail-closed, with actionable instructions and no automatic deletion or quota increase.

The UI confirmation explains preservation and possible reuse. The completion status distinguishes an existing identical checkpoint from a newly saved checkpoint. Unsaved changes without an identical verified copy still require free space and cannot be overwritten by Restore.

## Tests and evidence

New `localRestoreCheckpoint20261020.test.ts` checks verified identity, stale checksums, invalid shape, exact source/dataset/mapping/delimiter and named-source labels. New tests 8/8 plus the five existing history unit cases: **13/13 PASS**. Full frontend deterministic suite: **873/873 PASS in 116 files**. TypeScript/Vite production build passed.

The actual browser test `browser-full-history-restore-20261020.spec.ts` creates all 30 snapshots using real UI controls. It checks restoring both directions without a 31st snapshot, ordinary Save still refusing a full history, unsaved source preserved when a backup cannot be made, explicit deletion of one synthetic test snapshot, subsequent backup creation and restoration of the unsaved source, and refusal to trust a cached backup whose checksum was corrupted. All source values are authored synthetic examples, including Korean UTF-8; no customer logs or server-side version writes.

One early corrected-browser attempt ran zero tests because an isolated localhost port was already in use; the subsequent run used checked free loopback ports and completed **1/1 PASS**. This port-startup diagnostic is not counted as a test pass or a product failure. The final expanded scenario adds explicit-save and stale-checksum controls.

Immutable local evidence directory:
`/home/aella/.local/state/parserstudio-local-full-history-restore-20261020/`.
Baseline `browser-red.json`, focused `focused-units.log` and `browser-green-isolated.json`, full `full-units.log`, `web-build.log`, `backend-build.log`, and combined affected browser `regression-37.json` are kept separately. The latter contains 33 scoped cases plus 4 existing Local Versions journeys, not 37 new features. Final executed counts, hashes, exact commit and GitHub Actions status are recorded after completion in Issue #1 and the new Draft PR.

## Boundaries

No source parsing rules, backend APIs, authentication, credentials, deployment or target behavior are changed. This is browser-only preservation, not a backup across browsers or origins, recovery of deleted data, native Stellar import, two-human acceptance or release qualification. The old public beta and all previous Drafts/worktrees remain unchanged. Main merge, public development deployment, production, DP and sensor operations remain outside this work.

## Final local qualification

The combined actual Chromium run completed **37/37 PASS, 0 failed, 0 skipped, 0 flaky**: 33 current scoped browser cases plus 4 existing Local Versions cases, on real isolated Vite + source-pinned compiled authoring backend + in-repository Python Multi-Pass. Backend build also passed. No network response mocks were used. The five tested code/test/workflow file hashes were rechecked unchanged before commit.

| Evidence | SHA-256 |
| --- | --- |
| `focused-units.log` | `40912968aff8e80c905fc07aeee6120162ae8c1f1fa9fe23eebdbc81bb0db4ed` |
| `browser-red.json` | `6acc06189bedc6f6deab1b049142710963cd2e91702d8bca6fb02a27ec1e3a55` |
| `browser-green-isolated.json` | `51fc5e7526d27af99f8e4b5402eaff519902879982ddc6f0a966624e2da63c7c` |
| `full-units.log` | `fb735aea994517b444220da972b7275a1879521563fcd3b3a9d3d40d15f3c129` |
| `web-build.log` | `83ed906c8ba8d92587cdd315906df12fd04f2eb03ae7e5e61fe8d86e07c54796` |
| `backend-build.log` | `87cd3cf566da0f143d449cc01b50779a6e5d883f4c780637480d1ebbbd97d559` |
| `regression-37.json` | `17efb41b0b46e52b72dbe217c0bb325238274406c43ed4e7368e66d273071f78` |
