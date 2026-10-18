# P0-STD-77 — RFC 4180 Multiline CSV Original UTF-8 Source Spans

## Scope and normative boundary

- RFC 4180 (Informational), §2, defines CRLF-separated records, optional final record terminator, doubled quotes inside quoted fields, significant unquoted spaces, and CR/LF/CRLF inside quoted fields. The TEXTDATA rule excludes ASCII control characters and DEL.
- The parseRfc4180HeaderCsv entry point intentionally requires a safe, declared header with unique names and at least one data row; these are product guardrails, not universal CSV-format requirements.
- Existing explicitly isolated LF-only outer-record compatibility is retained but does not certify canonical RFC 4180 conformance for those rows. The parser conservatively rejects mixed outer record separators and malformed/ambiguous rows.
- Vendor-specific CSV position-to-field meaning, framing across a relay, schema rotations, source producer firmware variants, target Fluentd/Stellar behavior, and security event end-to-end correctness are NOT VERIFIED.

## Implementation

- Extend the existing bounded src/rfc4180Csv.ts state machine, not a second parser: original half-open UTF-8 field byte intervals, exact source lexemes and decoded values, header/row identity, logical record spans, physical newline counts, and terminator sizes. Entire source byte coverage must reconcile exactly.
- New src/utf8OriginalByteOffsets.ts computes a bounded, linear-time character-to-original-UTF-8 boundary index, rejects isolated surrogate code units, and avoids offsets created from re-serialized values.
- The same lexer owns both value extraction and source intervals. Quoted bare CR and mixed CR/LF/CRLF within quoted fields follow RFC 4180; C0/DEL outside permitted newlines are rejected. Quoted empty versus unquoted empty remains inspectable in source spans.
- All changes stay in an isolated source PoC worktree derived only from previous Draft PR #76 exact HEAD e5f08ac85d9de52e3fc6bccec8d6e5ede4bd2617. Do not touch product/main, native, DP, sensors, deployment, unrelated PRs, or existing dirty worktrees.

## Independent pinned authored oracle and RED/GREEN evidence

- scripts/poc/freezeStdCsvMultilineOriginalSpans.py freezes authored source text, original lexemes, independently stated decoded values, record/field intervals, sizes and source SHA before candidate evaluation.
- scripts/poc/standardCsvMultilineOriginalSpans.pinned.json SHA256 25c3f27ff07e13e37bf7ff78ad8fe05bac15143a496db61e5a7e9a95fe4eebff: 22 total (11 valid + 11 invalid) authored synthetics; 100 exact field/name/value/original-byte claims on valid cases, no manufacturer/device-wire claim.
- Initial RED on previous HEAD (9 missing original-span outcomes). Subsequent RED on candidate (6 RFC grammar/unsafe-control failures); after narrow fixes, focused suites 41/41 PASS. This demonstrates both new source-span extraction and independently spotted bare-CR/ASCII-control conformance errors.
- Historical source safety replays: 1,361 prior originals + 2,892 prior invalid mutations, including 197 existing REVIEW_ONLY not reclassified as successes, zero new invalid review, zero byte or UTF-8 span drift, zero auto-promotions, zero veto bypass. The separate 22 earlier scored source examples are safety only, not new holdout accuracy.
- Whole deterministic suite 208 files / 1,527 Vitest PASS. TS/Vite build and exact-head PR CI are separate required gates; consult their actual results rather than inferring from focused tests.

## Reproduction

~~~sh
python3 scripts/poc/freezeStdCsvMultilineOriginalSpans.py
sha256sum scripts/poc/standardCsvMultilineOriginalSpans.pinned.json
npm test -- src/poc/standardCsvMultilineOriginalSpans.test.ts src/rfc4180Csv.poc.test.ts src/poc/standardCsvWhitespaceSourceParity.test.ts
npm test
npm run build
npx --no-install tsx scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install tsx scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install tsx scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
~~~

Never promote documented or synthetic byte-level evidence to native, blind-manufacturer or full-event correctness.
