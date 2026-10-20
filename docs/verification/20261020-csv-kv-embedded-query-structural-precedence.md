# CSV positional source vs KV key/value precedence — browser / grammar fidelity

**Date:** 2026-10-20 KST
**Scope:** Isolated source fix stacked on approved Draft PR #114 (head `86b07b1388287a48ed134eed46e2e11c22b6ce32`). No main merge or public development deploy.

## Independently reproduced gap (RED)

Before this change, `classifyBody()` in `src/guided/autoParserEnvelope.ts` recognized a valid quoted CSV row beginning with `"` before the generic `=` KV hint, but treated other positional CSV with a URL query `=` as a malformed KV row. That changed the value-free source-accounting ledger to `BODY_MALFORMED` / `1 event needs attention` even when the already qualified strict `tokenizeCSV()` lexer proved the record had three valid columns. This is not a manufacturer-specific case.

New seven-test red/green suite: `src/guided/csvEmbeddedEqualsPrecedence20261020.test.ts`. On the base branch **4/7 FAILED**, precisely the four valid positional CSV sources containing URL query `=` (comma, semicolon, TAB, and quoted middle field); three KV/malformed controls passed. The authored fixtures include synthetic Korean UTF-8 log field values, never customer data.

## General grammar correction

- Preserve **complete key=value records** ahead of any positional CSV heuristic, including genuine KV values with embedded commas.
- For delimiter-bearing rows where complete KV grammar does **not** match, defer to the existing strict `tokenizeCSV` grammar over comma, semicolon and TAB, even if `=` occurs later in an unquoted or quoted CSV cell. Do not infer names or content semantics; positional CSV still requires the user's reviewed column names.
- Preserve **fail-closed leading KV signature** (`name=`) when its remaining bytes are malformed but happen to contain two CSV delimiters. Do not claim it is recognized CSV. Malformed embedded quotes likewise remain unsupported.
- All source bytes and values remain unchanged; only the local classification and beginner source-accounting guidance improve. No extra lexer or manufacturer-tailored regex was added.

## Executed local qualification

- Focused unit/regression across CSV grammar, envelope, and generic parser: **48/48 PASS** on four files.
- Entire frontend deterministic suite: **865/865 PASS**, 115 test files.
- Web TypeScript/Vite production build **PASS**, offline authoring backend build **PASS**.
- New **real Playwright CLI Chromium** browser test `tests/novice-csv-embedded-query-20261020.spec.ts`: **1/1 PASS**, zero fail/skip/flaky. Real locally bound Vite, offline authoring backend and Python Multi-Pass. Four synthetically authored CSV source strings traverse Add Logs -> Analyze Logs -> Review CSV column names -> select the actual separator. All four have `0 events need attention` in the ledger, `3 consistent columns detected`, and original source text unchanged. Schema review remains required; the Review Fields button cannot proceed without column approval. A malformed leading KV example still returns `1 event needs attention` and cannot advance. No mocked API responses, browser JS errors or API 5xx.
- Expanded exact-source regression in `.github/workflows/quality.yml`: **31/31 PASS**, **0 skipped, 0 unexpected, 0 flaky** across nine existing+new specs, one worker and zero retries. Real isolated Playwright CLI Chromium, current tree's built offline authoring compiler, in-repository Python Multi-Pass and localhost Vite; no DP, sensors or public deployment.

## Immutable local evidence

Root: `/home/aella/.local/state/parserstudio-csv-query-precedence-verification-20261020/`.

| File | SHA-256 |
| --- | --- |
| `focused-browser.json` | `80b567b69c9fb36652ecf9393d19c18441864dd0aaa4670391ae63b66cb5acf1` |
| `gated-31-browser.json` | `e9cc7ad139b9a58c79fec042328bf41d6842800ecfa516478e24916279ae21f9` |
| `full-unit.log` | `466ea7dca93152d27d8fe4b744228cc23ba518ced8e7e5527bcde049ab1b930e` |

`/tmp/parser-studio-csv-embedded-equals-red-20261020.log` preserves failing baseline; `/tmp/parser-studio-csv-query-focused-green-20261020.log`, `/tmp/parser-studio-csv-query-web-build.log` and `/tmp/parser-studio-csv-query-backend-build.log` preserve corrected focused/unit build results. The new Draft PR must separately pass GitHub Actions on its **pushed exact HEAD**, not inherit the earlier PR #114 green label.

## Release / external verification boundaries

These tests establish browser source classification and user review only. They do not certify manufacturer meaning, native Stellar parser upload/import, target-version behavior, DP or sensor delivery, two-human release acceptance or any production deployment. The previously owner-deployed public development beta `6c8f552eaf165622a2a23fa491443df5c57dc68d` remains untouched. PR #111–#114 stay Draft/unmerged until separately authorized.
