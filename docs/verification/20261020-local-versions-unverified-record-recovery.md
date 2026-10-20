# Local Versions — recover from unverified records at the bounded history limit

**Date:** 2026-10-20 KST
**Scope:** Local-only browser experiment versions, no server writes, no public deployment, no main merge.

## Actual user-visible failure (RED)

Browser-only IndexedDB history safely excludes records with invalid contract/content/SHA from restore, but those records remain in the same 30-slot local quota. A user with one validated version and 29 damaged or unverified entries sees **29 excluded** and **1/30 saved**, then receives **Local history is full** on the next save. The previous UI has no action to remove the unverified records, and deleting the sole valid version cannot repair the remaining 29 invalid records. This is a real novice recovery issue, not a backend parsing or manufacturer format defect.

The new Playwright CLI Chromium browser test injects synthetically invalid IndexedDB entries into its own isolated loopback browser profile, preserves one SHA-verified version and checks the full-capacity failure before the fix. The baseline returned a nonpassing E2E test because the **Delete unverified local versions** button did not exist. The earlier baseline run timed out while waiting for that missing control, after proving the 29 excluded entries and full-capacity error in the browser trace; this is **RED**, not a passing run.

## Browser-only user-controlled correction

- Show the rejected count, storage/quota impact, and an explicit **Delete unverified versions** option only when invalid entries exist. Describe that entries may contain sensitive raw log data and deletion is permanent.
- Require a positive native browser confirmation; cancelling leaves everything untouched. Never automatically delete, upload, export, log or synchronize any version contents.
- Enumerate the actual object-store cursor keys so malformed identifiers can be removed without treating them as valid version IDs. Independently check each entry with the **existing** shape and SHA verifier before choosing deletion candidates.
- Re-read rows inside a separate IndexedDB write transaction. Compare each candidate to its originally inspected content before deleting. If another tab modified a candidate, abort the transaction; do not delete a now-valid or changed record. Preserve all verified stored versions and the current workspace.
- Existing Save Version, compare, restore, browser-profile isolation, source retention and max-size limits remain unchanged. This user-initiated operation is not a general-purpose clear-all or a migration of stored customer data.

## Qualification and boundaries

- New actual Chromium end-to-end: create a validated Korean UTF-8 version, insert 29 unverified local rows (including a malformed ID), confirm the full-capacity error, cancel deletion and confirm no change, explicitly approve deletion, save a second version, restore the first exact original source, and assert zero API write requests. Only the verified snapshots remain.
- **Verified local results:** all deterministic unit tests **865/865 PASS across 115 files**, TypeScript/Vite production Web build **PASS**, offline authoring backend build **PASS**; previous local-version browser journeys **4/4 PASS**; new corrected recovery case **1/1 PASS**; expanded 10-spec exact-source scoped Chromium gate **32/32 PASS**, 0 fail/skip/flaky. All real isolated localhost browser services, same-source offline authoring backend and Python Multi-Pass, no mocked HTTP responses. The dedicated GitHub Actions browser gate is updated 31 -> 32 for its new exact-HEAD run.
- The local browser remains the authoritative holder of its original data. Quota/browser permissions still apply. Damaged records could contain sensitive data that this product cannot safely restore, so deletion requires explicit owner confirmation. This does not recover erased browser profiles or deleted versions, nor does it validate Stellar native import, production/DP/sensor operations, or full release acceptance.

### Evidence

Local immutable verification directory: `/home/aella/.local/state/parserstudio-local-invalid-version-verification-20261020/`, with the actual baseline `browser-red.json` and following SHA-256-confirmed qualification files:

| File | SHA-256 |
| --- | --- |
| `browser-green-confirmation.json` | `0aead9c68fdae19e2fe5dac91f48e9749d2863787ab53b2a314b5cf316feb13a` |
| `full-units.log` | `b5c3e8aedd394affc9912dd1d8298c3219fbab319a526cf452c2cf91e838d249` |
| `final-web-build.log` | `f34226eeabbcaecbcbacece40696d1bfed9b26f91027abd5615f378799a72c32` |
| `backend-build.log` | `87cd3cf566da0f143d449cc01b50779a6e5d883f4c780637480d1ebbbd97d559` |
| `existing-local-versions.json` | `5311519d3a187c6dbfc9841be0d41d1f0d5db862ec6919c0073cd56ddd8a3944` |
| `scoped-32-browser.json` | `9076d04fa67b8a43952534e9c4be97ef14c4025b3bf2c323ed6dbdddef593825` |

The exact committed Git HEAD and subsequent GitHub Actions run must be checked separately from these local results; no exact-HEAD CI success is inferred from local testing.
