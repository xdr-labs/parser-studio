# 2026-10-25 Novice Security Parser — Actual UI / Native QA

## Scope and provenance
- Accepted product baseline: `xdr-labs/parser-studio` main `c73733138e3786b9c4197cf26100bafde89d9f0a`.
- Real public development UI: `https://app.parser.xdr.ooo/`. Chrome/Chromium was driven with the Playwright CLI, not an API-only shortcut.
- First-time user checks: paste original logs, enter vendor/product, run Auto Parser, observe Multi-Pass API event statuses, verify SHA-256 source identity, open field inspector where enabled, and use manual ChatGPT preparation + clipboard when partial/raw.
- Corpus: 30 scenarios selected for deeper UI review from the preserved 78-case security manifest, plus 10 preserved security-model examples. Publisher-documented excerpts, compacted examples, and explicitly synthetic cases are mixed; this is **not** 40 independent vendor device captures.
- Public baseline: **40/40 UI tests passed**, zero observed automatic external AI requests or browser-page JavaScript errors. Source-level PARSED/PARTIAL/RAW_ONLY must not be conflated with full native extraction.
- Original security manifest and detailed browser artifacts remain local to dev-atlas; no raw security/customer logs were committed.

## Actual GPT-6-authored recovery in the user UI
- Cisco Umbrella DNS CSV, Microsoft Windows Event XML, Cisco Snort IDS: **3/3** revised ParserRecipe v0.2 inputs accepted, source + two explicitly synthetic distinct additional events locally evaluated, user approval recorded through actual UI controls, downloadable **Ruby + CONF** pairs created, Ruby callbacks executed against the original and both variations, and original literal values checked.
- These three recipes were authored for this QA flow using the current assistant, not an independently authenticated external ChatGPT completion. A passing synthetic holdout is not external producer certification, blind generalization proof, or Stellar Cyber target verification.
- The first attempts failed safely: an overly long Snort regex violated the <=256-character bounded rule, and one additional synthetic log per case did not meet the existing two-unique-holdout minimum. No parser files were generated for failed attempts.
- After shortening the regex and supplying two distinct records, the three real browser/native workflows passed. The application correctly enforced safe review before generation.

## Observed novice usability defect and bounded fix
The existing `Test Proposed Fix` button could be used after pasting only one additional event, even though the independent-example comparator requires at least two. It then reported only `Additional logs tested: NO` and `Overall test: FAILED` without telling the user the required minimum. This looked like a parser failure, but was a missing user instruction.

The fix adds a one-line explanation beside the input and a **local preflight** using the existing `assessHoldoutIndependence` contract. If evidence is too small or overlaps the original, the UI shows the required count or the overlap warning before running a parser candidate. `Test Original Sample Only` remains available as an explicitly limited DRAFT; no API, parsing grammar, permission or security behavior was expanded.

## Tests against the source candidate
- `npm run typecheck`: PASS.
- `npm test -- src/guided/ChatGPTAssist.beginner.test.tsx src/guided/autoParserRegression.test.ts`: **12/12 PASS**.
- `npm run build`: PASS.
- Playwright CLI, isolated source-built Vite + existing loopback development backends: `PARSER_STUDIO_SCOPED_AUTHORING_E2E=1 playwright test --config=playwright.novice-local.config.ts`: **1/1 PASS** (one holdout gives precise preflight guidance; two valid holdouts qualify).
- Previously accepted current-main public Chrome baseline was not restarted or overwritten. This change has not been publicly deployed or merged by this QA branch.

## Boundaries
External authenticated ChatGPT first/second/third response accuracy remains **UNMEASURED** (historical provider HTTP 429 credit exhaustion). These checks do not validate native Stellar Cyber 7.0 ingestion, DP/sensor receipt, source-vendor firmware compatibility, or preservation of every nested array mapping. Do not claim otherwise.
