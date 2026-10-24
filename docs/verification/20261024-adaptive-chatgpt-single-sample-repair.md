# 2026-10-24 — Single-source Adaptive ChatGPT Repair

## Change boundary

- Started from the exact, already installed development integration HEAD `2ab2e74dbc681242f07a9f6580794cc4e07ac970` in an isolated worktree and feature branch. Existing integrated development deployment and source worktrees were not changed.
- Supports the existing **manual** ChatGPT prompt copy / JSON paste path; no provider API, authentication, credentials, telemetry, automatic third-party log transfer, production, DP, sensor or Stellar target operations.
- Keeps current ParserRecipe v0.2 REVIEW_ONLY schema, source SHA-256, project identity, physical record count and strict native artifact gates.

## Implemented

1. `chatGptAdaptiveRepair.ts`: deterministic local failure classification and targeted second/third prompt. Carries the complete canonical source prompt and prior untrusted response encoded as a JSON string; validates local diagnostic codes and bounds the prior response to 12 KiB. Third try may change supported parsing strategy for a genuine extraction or holdout failure. No fourth automatic try.
2. `ChatGPTAssist.tsx`: offers **Copy Improved Prompt** after invalid, untranslatable, regressed or failed native compilation results. Clears stale parser candidates when a retry begins and preserves user-authorized copy/paste boundaries.
3. A **Test Original Sample Only** path when there is no independent holdout. Runs the actual candidate on the unchanged original sample and existing regression checks, preserves the existing independent holdout path, displays extracted and normalized values, requires a separate explicit sample-only approval before DRAFT generation and clearly labels absent independent evidence. No silent rule apply.
4. `singleSampleVariation.ts`: optional bounded single-record IP substitution for CSV/KV/regex grammar. Apply the probe **only when that exact IP is already extracted as a source field**; logs whose parser does not expose that IP are NOT_APPLICABLE, not incorrectly rejected. Re-run an eligible candidate against an ephemeral, locally mutated source and require the same extracted field path to reflect the changed value. This detects some over-fitted value literals but is neither vendor evidence nor independent holdout.

## Test evidence

- Full frontend Vitest: **1,192/1,192 PASS** across **153 test files**, including 8 added focused unit tests. No skipped tests were presented as passes.
- TypeScript `tsc --noEmit`: PASS.
- Vite/TypeScript production Web build: PASS.
- **Real isolated Chromium Playwright: 19/19 PASS**, against the **same feature source** plus pinned, built local authoring backend and in-repository local Multi-Pass service. Included new one-log invalid first answer → retry → source-only draft and 3-attempt cap; existing actual full-recovery Ruby/CONF path; seven controlled security-format answers, full-recovery CSV with real independent holdout, Windows XML refusal; irregular log hints and identity-sensitive prompts.
- New browser path downloaded genuine CONF and confirmed DRAFT generation; this was a **controlled JSON answer**, not an independently invoked external ChatGPT model.
- The existing development deployment at `https://app.parser.xdr.ooo/` was neither replaced nor reconfigured. No post-deployment claim for this feature.

## Nonclaims / gates

- External independently invoked ChatGPT response quality: **NOT TESTED**, not an improvement percentage. The browser test uses known, controlled ParserRecipe responses to verify the application.
- One input log proves only its own extraction, mapping and bounded local synthetic invariants. It does not prove generalization to unseen security event types or manufacturer-specific field semantics.
- Real Stellar Cyber 7.0 installation, sensor reception, DP processing and release: **NOT VERIFIED / OUT OF SCOPE**.
- GitHub Actions hosted green status, main branch promotion and public development rollout are separate downstream gates. This isolated change must not be called deployed merely because tests pass.

## Source / tests

- `src/guided/ChatGPTAssist.tsx`
- `src/guided/chatGptAdaptiveRepair.ts` and `.test.ts`
- `src/guided/singleSampleVariation.ts` and `.test.ts`
- `tests/chatgpt-adaptive-single-sample-20261024.spec.ts`
- Original 19-case log: `/tmp/parserstudio-adaptive-final-chromium-20261024.log`
- Original full frontend log: `/tmp/parserstudio-adaptive-full-vitest-20261024.log`
