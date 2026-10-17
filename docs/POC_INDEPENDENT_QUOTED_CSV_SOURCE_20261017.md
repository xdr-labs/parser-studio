# Independent quoted CSV source/byte fidelity and conditional record framing (2026-10-17)

## Owner goal and strictly isolated scope

This source-only proof of concept is stacked exclusively on the separately verified Draft PR #48 exact HEAD `c03d167056798164e7779a7d7fd1699c5669ae3a`, itself stacked on PR #47 and PR #46. Qualified product **Multi-Pass + Generic Structural + bounded Funnel** is untouched. This branch does not change main, native Stellar/Fluentd compilers, deployment, DP, sensors, release, credentials or any earlier PoC worktree; product exact HEAD `da94aa9177c6b652eee47768efb98a9d47df8c5e` is preserved.

The purpose is **general source-structure accuracy**, not device-specific escape patches: quote doubling, embedded delimiters, embedded line breaks, one/two-column records, literal empty quoted cells versus independently configured unquoted nulls, and exact UTF-8 byte ranges. No unlabeled CSV cells are promoted to independently proven source field *names*.

**Hard safety boundary:** the new stage requires a separately established `CONFIRMED_SINGLE_CSV_RECORD` framing contract before it can suggest any CSV fields, especially when original quotes contain newlines. Without explicit framing it is byte-for-byte identical to the preceding PR #48 arbiter and does **not** automatically detect, merge or certify records. This context is a precondition for lexical review, **never an external self-certification of correctness**.

## New publisher-original truth pinned BEFORE any scoring

- `logstash-plugins/logstash-codec-csv@7866e8b15788d782b51f4e179e8a784c0dbdeab0`, `ruby/csv@9255c5e4f916e37de4004b7549dd5ae9354008c1`, and `apache/commons-csv@e07e3dfed1a73ed2001ce5ef545651ad3b198685`. Publisher licenses Apache-2.0, BSD-2-Clause and Apache-2.0.
- Three source test files, **122,140 original bytes**. Before comparing any candidate result, upstream exact commits/paths/original file SHA-256 and rights were frozen with manifest SHA-256 `d0db88056420f6fa7455c6833d5f00be8b6a104c012f374278f681093a8eb049`; public metadata: `scripts/poc/independentQuotedCsvSources.pinned.json`.
- A **separate Python lexical byte-oracle** derives original UTF-8 start/end offsets and raw literal slices from untouched upstream test source, checking decoded values against the third-party authors' **own Ruby assert_equal / Logstash RSpec assertions**. It does not import any Parser Studio parser or use any TypeScript output to generate expectations.
- Before the first candidate run, its source/case eligibility and golden were frozen as `author-expected-original-csv.v1.json`, SHA-256 `21df0514536935d5361e73b5cfbc4a263f8eb796caf27e4214e380d38a29427b`. Public metadata: `scripts/poc/independentQuotedCsvOracle.v1.pinned.json`. The original messages, asserted values and raw golden stay private at `~/.local/state/parserstudio-independent-quoted-csv-20261017` (0700 directory/0600 files); no private logs or source goldens are committed or uploaded.
- **Immutable 45-case selection:** **28** original, independently expected *positional CSV cell* events / **73** decoded lexical value + source-byte triples; **15 duplicate originals excluded**, **one** original two-input header/data session with **3** independently author-asserted *source header-name + row-value + row-source-byte triples*, **one** explicit header-uniqueness negative control under the publisher's separately declared strict profile.
- Preserve attribution: the Apache Commons duplicate-header test is invalid **only under its explicit `allowDuplicateHeaderNames=false` policy**. It is not evidence the parser automatically recognizes a globally invalid CSV wire event.

### Same frozen denominators (never combine unnamed cells with named source fields)

| Independent metric | Existing qualified positional source lexer | New isolated framed CSV source stage |
| --- | ---: | ---: |
| Scorable original standalone position-only rows | 28 | 28 |
| Qualified original positional value + exact UTF-8 byte-span TP /73 | **30** | **73** |
| FP / FN within these exact positional reference slots | **4 / 43** | **0 / 0** |
| Entire event exact on **only asserted positional cells** | 6/28 | **28/28** |
| Original separately supplied CSV header record → named row fields | Prior source observer did not link them | **3/3 exact** |
| Independently invalid strict duplicate-header profile veto escape | Not a source-parser qualification | **0** |
| Source/raw byte drift, auto promotion or >8 branch | 0 | **0** |

These are conditional **lexical source byte/span accuracy results**, not global CSV, vendor device, product or native parser success rates. Pre-existing product CSV extraction may already decode some events, but it was not assessed here for independently comparable per-cell source byte spans; the new layer is PoC-only and NOT part of the shipping parser.

### Structural recurring gaps corrected without manufacturer-specific rules

| Independent original category | Prior TP/FP/FN | New TP/FP/FN |
| --- | ---: | ---: |
| Doubled quotation marks | 18 / 1 / 2 | **20 / 0 / 0** |
| Embedded quoted CR/LF | 0 / 0 / 22 | **22 / 0 / 0** |
| One/two-column originals | 0 / 0 / 11 | **11 / 0 / 0** |
| Explicit unquoted null / empty quoted string | 6 / 3 / 8 | **14 / 0 / 0** |
| Already supported quoted columns | 6 / 0 / 0 | **6 / 0 / 0** |

The new `src/poc/independentQuotedCsvSource.ts` is a strictly bounded RFC4180-style scanner with original source UTF-8 byte replay, no unspecified escape decoder, duplicate/unsafe header-name rejection, a maximum of 256 columns and 16 KiB original input. It stores **positionalClaims** without fabricating a source key name. **namedClaims** are emitted separately and only when a byte-retained original header record is explicitly provided and each original header name is independently located. The original header and data remain **two distinct source messages**, never silently concatenated.

All outputs remain `RAW_ONLY`, `ABSTAIN_UNSAFE`, `REVIEW_ONLY_POSITIONAL` or `REVIEW_ONLY_NAMED`, with `autoPromoted=false`, `independentOracleCertified=false`, `nativeVerified=false` even after a caller's claimed positive profile. All three negative independent VETO conditions fail closed. Ambiguous quoting, stray control bytes, unsupported original column-name syntax, conflicting headers, and unqualified framing are never reported as completed source/native parses.

### Safety-only historical replay (NOT fresh accuracy)

Replayed **1,361 previous original security events + 2,892 previously known-invalid mutations**, including the historical **197 syntactically REVIEW_ONLY invalids**. Verified against the unchanged preceding #48 arbiter: **0 result changes, 0 new malformed review, 0 byte/span drift, 0 automatic success, 0 branch budget breach, 0 negative VETO bypass**. Also retained **22 previously scored independent CEF/Syslog/LEEF original events**, all byte-for-byte unchanged. These are regression safety checks, **not additional new source-accuracy TP**.

## Reproduction and CI closure

```bash
python3 scripts/poc/pinIndependentQuotedCsvSources.py
python3 scripts/poc/freezeIndependentQuotedCsvOracle.py
node_modules/.bin/vite-node scripts/poc/scoreIndependentQuotedCsvBaseline.ts
node_modules/.bin/vite-node scripts/poc/scoreIndependentQuotedCsvCandidate.ts
node_modules/.bin/vite-node scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
node_modules/.bin/vitest run src/poc/independentQuotedCsvSource.test.ts src/language-policy.test.ts
npm run typecheck
npm test
npm run build
```

Expected source original oracles reside only in a secure private directory; GitHub CI cannot and must not upload them. Before calling a new Draft PR fully verified, require the **same pushed exact HEAD** CI to independently succeed in deterministic unit tests, typecheck/build, real Chromium user scenarios, pinned backend build, and actual Chromium ↔ localhost HTTP integration. If any of those fail, do not claim successful release readiness.

## Explicitly unqualified / next evidence

External framing needs separately authenticated upstream evidence before multiline CSV may be interpreted as a single event; a caller's claimed profile alone **never certifies** original source/producer semantics. This PoC does not claim unframed Palo Alto traffic CSV column names, configurable single-quote escape dialects, CEF/LEEF escaping beyond separately qualified lexemes, unknown producer firmware wire behavior or native Stellar/Fluentd correctness. Existing **197/2,892** incorrect syntax-only review risks remain unresolved. New mixed-envelope/quoted KV goldens need genuinely new independent publisher sources pinned before comparison, not post-hoc selection.

Product backlog **R1 P0 Juniper/Defender/Umbrella, R2 beginner progress, R3 owner UI mapping/visual acceptance, R4 exact product-HEAD Full User E2E/release gate** is HANDOFF ONLY. No product integration, main change, deployment, production, merge, or release is authorized.
