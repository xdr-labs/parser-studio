# Source field and official normalization target type scopes — generic compiler closure

**Date:** 2026-10-20 KST
**Implementation:** Isolated developer-only Parser Studio worktree, not main, production or the public Web deployment.

## Evidence-driven R1 browser discovery

The owner's remaining parser-completion roadmap included two older examples: homogeneous endpoint JSON and consistent wide quoted CSV. Before adding code, exact deployed public development candidate 6c8f552eaf165622a2a23fa491443df5c57dc68d was exercised with synthetic, explicitly bounded three-event examples in real Chromium (normal trusted HTTPS, no HTTP response mocks).

- **Homogeneous endpoint JSON:** 3/3 original objects structurally extracted, Review Fields -> Map Fields -> Create Parser -> generated DRAFT Ruby and CONF all completed. The old roadmap's generic endpoint compiler gap does not reproduce on this accepted JSON subset; no redundant repair was introduced.
- **Homogeneous 23-column quoted CSV:** 3/3 source events and 23 exact columns correctly recognized and manually named; quoted URLs containing equal signs and commas, escaped quotes, original Korean username values, and one empty final column were retained. Review Fields succeeded, but **Map Fields showed three blocking TYPE_ERROR findings** and the Create Parser button was disabled.
- The offending source-to-destination mapping is severity -> vendor-local severity, with user-value type **string**, source values medium across three records. The UI correctly indicated it was a *vendor* namespace mapping; it was NOT a reviewed standard Stellar severity integer target.

## Root structural error

The normalization validation function unconditionally invoked the official target-specific value validator on the bare mapping target name. Its official Stellar severity numeric range (0..100), and the official srcport/dstport semantic range, inadvertently governed equally named vendor-only fields, even though the downloaded parser emits those under the parser's vendor namespace.

**Generic correction:** When the explicit field group is vendor_fields, check the user-selected mapping value type via the existing conservative type validator. When the group is an approved official Stellar group, preserve the existing stronger official target semantic/range constraints exactly. Do not change the parser engine, create vendor-specific Regex rules, coerce qualitative severity to numbers, auto-approve a dictionary mapping, or override saved manual mappings. Legacy callers without an explicit group retain their previous validation behavior.

## RED -> GREEN and safety

- Six new source-independent unit cases cover categorical vendor severity, text-only vendor port-like field, exact user-selected type enforcement for vendor fields, explicit official severity qualitative rejection, official severity upper/lower range checks, and distinct custom targets.
- On unmodified code: **2 of 6 new unit cases RED** (false TYPE_ERROR for vendor severity and vendor port); existing safety cases remain GREEN.
- After generic group-scope correction: focused normalization candidate/validation suites **18/18 PASS**; official severity upper range and qualitative-value rejection remain enforced.
- Real local Vite + same source Python Multi-Pass + real offline authoring backend Chromium: the new source-preserving test performs full manual 23-column CSV review, Map Fields no-blocker inspection, DRAFT Ruby+CONF generation, Ruby download and decoded 23-column backend recipe equality, verifies no original personal example value in exported Ruby, and returns to Add Logs to confirm exact original unchanged.
- The first browser script had a test-only navigation error after DRAFT generation, attempting to locate an Add Logs textarea from the Create Parser stage. No product defect was present in that assertion; corrected test navigates back before checking original source. Only the corrected passing run qualifies.
- Dedicated existing CI browser gate is expanded from 28 to 29 real Chromium user tests, retaining all 28 existing scenarios and requiring 0 skips, unexpected failures or flaky cases.
- No proprietary manufacturer original, firmware or native target oracle was provided. New coverage qualifies **generic explicitly declared single-line CSV and safe DRAFT generation**, not all Cisco Umbrella/Defender firmware releases or Stellar Cyber imported runtime.

## Files and release protection

- Source implementation: src/guided/normalizationValidation.ts.
- New unit oracle: src/guided/normalizationVendorTypeScope20261020.test.ts.
- Real user browser path: tests/novice-vendor-field-collision-20261020.spec.ts.
- Required CI count: .github/workflows/quality.yml, 29 exact executed Chromium tests.
- Developer development site stays at the previously authorized deployed SHA 6c8f552e, prior HTTPS Full User E2E 134/134 PASS. New source candidate is a separate Draft PR; it is **not deployed**, does not change existing parser/source statuses, and cannot be represented as current public functionality until a separately approved deployment.
- Original empty extra column is preserved as a CSV source position. It is not automatically added to normalized output without a nonempty reviewed value, which is consistent with the existing mapping policy.
- Native/target Verified remains false; no Stellar DP, sensor send or production deployment.

## Precommit exact-source test evidence

- vendor-scope-browser-fixed.json: SHA-256 fd93d8f4ab783744c6821677528532c15725845ce1b14321857e30206e9a170d; local path /home/aella/.local/state/parserstudio-r1-real-browser-diagnostics-20261020/vendor-scope-browser-fixed.json.
- precommit-gated-29.json: SHA-256 f705536fa06832f15e811ded18116ae15d36a82ba4f3a5fa70ef7e98d7350a28; local path /home/aella/.local/state/parserstudio-r1-real-browser-diagnostics-20261020/precommit-gated-29.json.
- vendor-scope-web-build.log: SHA-256 ac1e2ebc330cb764e7e507b28651037f8265284ffed7107e8c7047e24bcc4c14; local path /home/aella/.local/state/parserstudio-r1-real-browser-diagnostics-20261020/vendor-scope-web-build.log.
- vendor-scope-backend-build.log: SHA-256 87cd3cf566da0f143d449cc01b50779a6e5d883f4c780637480d1ebbbd97d559; local path /home/aella/.local/state/parserstudio-r1-real-browser-diagnostics-20261020/vendor-scope-backend-build.log.
- The full 29-case browser gate ran over real loopback Vite+Authoring+Multi-Pass, 1 Chromium worker, no HTTP mocks and no retries. **29 PASS, 0 FAIL, 0 SKIP, 0 FLAKY**. The separate corrected 23-column CSV user scenario was **1/1 PASS**. These are pre-commit locally observed tests, not the subsequent exact-HEAD Actions run.
