# Explicitly quoted two-column CSV — safe beginner review and DRAFT flow

**Date:** 2026-10-20 KST
**Base:** Draft PR #116 HEAD `0021de3313392f70fbae1728bcfd46b8bf25715b`
**Scope:** Isolated source improvement in Auto Parser's existing guided flow, no third creation method, no public deployment or main merge.

## Reproduction and structural rationale

Parser Studio's common strict browser/native-aligned `tokenizeCSV` lexer already supports two columns, doubled quote escapes and comma/semicolon/TAB delimiters. The event-accounting ledger intentionally required three fields to prevent promoting ambiguous short text such as `allow,198.51.100.10` to a verified CSV candidate. However, this also reported **all** clearly delimited, fully quoted pairs such as `"allow","198.51.100.10"` as needing attention. The novice could not reach a reviewed CSV path, even with explicitly supplied field names. This is a generic candidate-evidence gap, not manufacturer-specific parsing logic.

New deterministic RED suite: `src/guided/quotedCsvPair20261020.test.ts`. At base, **5 of 10** new cases failed: comma, semicolon, TAB, doubled-quote and embedded delimiter variants. Five rejection/ambiguity controls remained safe.

## Bounded generic improvement

- The ledger first invokes **the existing strict `tokenizeCSV` lexer**. Three or more lexically valid columns continue using their established behavior.
- For exactly two fields, promote only **fully quoted pairs with an actual quoted-field boundary** (`"` + delimiter + `"`). Do not promote unquoted two-column text, malformed quote transitions, invalid delimiters, or partial trailers.
- This recognition means structurally detected CSV only, never known manufacturer meaning or verified column names. `assessEnvelopeCompilation` continues to require explicit CSV column review (`COLUMNS_REQUIRED`).
- After the user confirms names matching the actual selected separator and shape of **one fully recognized standalone two-column CSV family**, the guided UI applies that explicit source decision to the existing CSV browser preview. Wider CSV shapes retain their pre-existing automatic mapping flow. It does not silently apply to mixed, unknown, partially parsed, mismatched or non-CSV sources. The next steps still require field-mapping review and backend capability/DRAFT qualification. An initial 34-case integration run detected a regression in the established 23-column mapping: treating all already-recognized CSV widths as an explicit format reset removed a formerly qualified vendor-local severity mapping. That failed gate is preserved; the correction limits the format transition to strictly qualified two-column source. The prior 23-column scenario and both new two-column scenarios then passed together (3/3), before the full gate was re-run.
- The **Keep all values with temporary names** action applies the same explicit reviewed format decision to a valid homogeneous CSV; source edits revoke review approval. Neither path sends raw logs to an external AI provider or changes the two authoring methods.

## Real verification and release boundaries

- New Playwright CLI Chromium scoped cases:
  1. Paste three safely quoted two-column rows; see zero source events needing attention; Analyze Logs; explicitly approve `action,src_ip` names; Review Fields; Map Fields; generate/download reviewed DRAFT Ruby; decoded project retains original positional schema/delimiter; source bytes unchanged.
  2. Independently apply safe temporary names for synthetic Korean UTF-8 two-column CSV; a changed/malformed source immediately revokes parser review readiness.
- Existing unit/Playwright tests remain mandatory on the same candidate. Extended exact-source browser gate in `.github/workflows/quality.yml` goes from 32 to **34**, zero skip/fail/flaky. Local test output directory: `/home/aella/.local/state/parserstudio-quoted-two-column-csv-20261020/` with the baseline RED test, focused tests, both new browser cases, full units/build and 34-case browser evidence.
- All examples are synthetic, not verified manufacturer originals. DRAFT generation and download do not prove actual Stellar DP import, receiver output, sensor data, native engine or production compatibility. The owner-approved public beta remains unchanged at prior HEAD `6c8f552eaf165622a2a23fa491443df5c57dc68d`. No main merge, public deployment, DP, sensor or release acceptance is performed.

### Measured developer-only evidence (same candidate)

- Full frontend Vitest: **875/875 PASS** across 116 files.
- New guided Chromium cases: **2/2 PASS**. Combined old 23-column and new two-column focused browser regression: **3/3 PASS**.
- Expanded exact-source local Chromium: **34/34 PASS**, 0 skipped, 0 unexpected, 0 flaky, 1 worker, 0 retries.
- Browser and backend build: PASS. GitHub pushed-head CI must still qualify the committed revision independently.

| Evidence file in `/home/aella/.local/state/parserstudio-quoted-two-column-csv-20261020/` | SHA-256 |
| --- | --- |
| `unit-red.log` | `4940f2640ac5e429237439ba13ae2935b3dab9cfa96574934fb0c71cda1f6baf` |
| `focused-post-fix-browser.json` | `bf004bc81bc2ec9f858e8dfd912ba2d1ec3e3e0054855bd849553409a6bd870e` |
| `browser-focused-2.json` | `69f16898d6e6a8311db5e4e456f69f64dde3c2656cf85adc5bb0c97a4c03ec67` |
| `full-units.log` | `ac16497d743166e8fc3995c41e2bea7c6954120875b3d2fdaf7be838e3e77010` |
| `web-final-build.log` | `998ed21d9ed397da15693832bf11fd7e58c2a3be1df338952ffc56586da1fc7a` |
| `gated-34-browser-final.json` | `926f9f36c93f443f60697cc96106afc48f23e51831d796ba44661192b015271d` |
