# Strict CSV source-accounting lexical fidelity — shared grammar correction

**Date:** 2026-10-20 KST
**Worktree:** `poc/csv-grammar-consistency-20261020`, stacked on Draft PR #113 exact base `ef82c04de5b6289bd27bf293cfcae6b51ca1e65f`.
**Scope:** Developer-only source and isolated localhost Chromium, no main merge or public development deployment.

## Reproduction and generic fix

The Auto Parser event-accounting ledger previously counted separators while simply toggling quote state. It could incorrectly classify malformed CSV source as `RECOGNIZED`, including a quote inside an unquoted value and non-whitespace bytes after a closing quote. Five deliberately malformed, synthetic CSV examples fail the new strict unit regression on the unmodified base. This is a generic CSV grammar disagreement between the ledger and actual CSV field extraction, not a manufacturer-specific problem.

The source-accounting `csvValid` check now delegates lexical validation and field width to the **existing** strict `tokenizeCSV` implementation in `src/parser.ts`, across comma, semicolon and TAB. The lexer remains conservative and aligned to the existing backend's strict CSV parser contract. At least three lexically valid fields are required for a ledger CSV candidate; **field names are not inferred** and must still be reviewed before draft generation. No independent parser/lexer was introduced. Explicit KV `key=value` events keep their existing precedence.

The beginner event-accounting UI also correctly uses singular agreement: **`1 event needs attention`** for a malformed individual event, while retaining **`0 events need attention`** for zero and ordinary plural forms.

## Deterministic and real Chromium acceptance

- New `csvEnvelopeLexicalFidelity20261020.test.ts`: 11 cases — five invalid quote transitions, five valid RFC4180-style quotation/delimiters, and KV precedence. Existing envelope/parser/draft-focused suites plus new cases: **47/47 PASS**.
- Web production build: `npm run build` completed (TypeScript + Vite). After the final test-only delimiter correction, full `npm test`: **858/858 PASS across 114 test files**; final TypeScript + Vite production build also **PASS**.
- Real focused Chromium `novice-csv-lexical-accounting-20261020.spec.ts`: one browser test loops over **five malformed and four valid** synthetic CSV events with exact input preservation and ledger checks. Malformed input remains `BODY_MALFORMED`/needs-attention and cannot advance to field review. Valid rows pass lexical detection but cannot advance without explicitly reviewed column names. The test deliberately selects the actual semicolon or TAB delimiter before asserting the safe three-column suggestion; the UI initially defaults to comma. **1/1 PASS, 0 FAIL/SKIP/FLAKY.**
- Expanded existing exact-source scoped browser gate, across eight specs: **30/30 PASS, 0 FAIL/SKIP/FLAKY.** Executes real Chromium, Vite, offline authoring server and in-repository Python Multi-Pass over independent `127.0.0.1` ports, one worker, zero retries, no mocked API responses. Preserves 29 qualified preexisting browser scenarios including reviewed event families, separate log-type handling, source/container cases, dual-profile storage isolation and vendor-local CSV normalization.
- Prior first focused run failed on the grammatically incorrect UI singular, which is fixed and rebuilt. A subsequent focused script failure was a **test expectation error**: semicolon/TAB records were still checked against the initial comma selector. The test now explicitly models user delimiter selection. Neither failed run is represented as a product acceptance PASS; the final passing browser JSON files are authoritative.
- Prior Draft PR #113 exact CI [#39349404607](https://github.com/xdr-labs/parser-studio/actions/runs/39349404607) independently finished **COMPLETED SUCCESS** at HEAD `ef82c04de5b6289bd27bf293cfcae6b51ca1e65f`. That success does not qualify this new uncommitted CSV change; it requires its own new exact-HEAD CI.

## Immutable local precommit evidence

All evidence under `/home/aella/.local/state/parserstudio-csv-grammar-verification-20261020/`:

| Artifact | SHA-256 |
| --- | --- |
| `web-build.log` | `0446e4b61bbe9fc254ed2e247deda03aaf2e09302fb8eb295b5b944c0e240555` |
| `focused-units.log` | `2587aa1563af4e4f4c0f2b8192e005a08eca1a86edf99a08e3962088280ffa36` |
| `focused-csv-browser-fixed.json` | `eed2c109917c0aed97ea62091d123d047bffb4abe8b681c4dd60a9bb6f71b208` |
| `gated-30-browser.json` | `82b86077d259260ed6b8762e384fec877e515ef68d26014990f824bc273a746c` |
| `full-unit.log` | `344d0754c5d06a498c71ad734d0f293f0b5c521747b19efc11475332d3f977ec` |
| `final-web-build.log` | `07748ba754feb0c20b660e38671cfbcea32d53a7b234ee6988c49ec5367ec928` |

## Scope and limits

Source-change files are `src/guided/autoParserEnvelope.ts` and `src/guided/AutoParser.tsx`; regression files are `src/guided/csvEnvelopeLexicalFidelity20261020.test.ts` and `tests/novice-csv-lexical-accounting-20261020.spec.ts`. CI `.github/workflows/quality.yml` increments the focused gate from 29 to 30. Original UTF-8 values, event boundaries and source accounting remain intact. These samples are authored, not authenticated manufacturer originals; no manufacturer semantic F1, native Stellar import, public beta on this exact source, DP, sensor or production acceptance is claimed. Existing public development application is unchanged at prior owner-approved HEAD `6c8f552eaf165622a2a23fa491443df5c57dc68d`.
