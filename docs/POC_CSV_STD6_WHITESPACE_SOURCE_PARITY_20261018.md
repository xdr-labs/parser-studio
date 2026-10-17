# P0-STD-6 — RFC 4180 CSV field whitespace and source-byte parity

## Source standard, scope, isolation

Canonical reference: RFC 4180 section 2,
https://www.rfc-editor.org/rfc/rfc4180
(informational): ordinary unquoted spaces are part of field data and should
not be discarded; embedded delimiters/double quotes require quoting;
within quoted fields, double quotes are escaped by doubling, and characters
after the closing quote must be the delimiter or record boundary.

This is a strictly isolated source/browser single-record grammar PoC,
branched from first qualified standards audit PR #56 exact HEAD
2335895dbf8c9f3c6f67c1ff8b468f2a8f9f20e6. Product/main and prior
Draft PRs are not changed. No native/DP/sensor/production/deployment
or merge work.

## Pinned expected evidence before candidate execution

Independent author script scripts/poc/freezeStdCsvWhitespaceSource.py,
SHA-pinned fixture scripts/poc/standardsCsvWhitespaceSource.pinned.json,
SHA256 02ec194375d84f36b9dc78e4c0bb9c8b298c43bbbbeb96809e2eaaa67be9f09e.

14 synthetic standards-derived controls: 9 narrowly valid and 5 invalid.
For every valid source field the answer freezes column ordinal, original
unmodified lexical value, decoded value, quoted flag, original UTF-8 byte
start/end, and a conditional nullable-source interpretation. Deliberate
controls include leading/trailing unquoted whitespace, quoted/unquoted
empty, UTF-8, doubled quotes, comma within quotes and final empty cells.
Invalid cases include unterminated quoting, spaces before/after quoted
cells, embedded quotes in unquoted values and trailing junk after quote.

These are not producer/native or external manufacturer holdout goldens.

## Confirmed RED -> shared-grammar GREEN

- RED on unchanged PR #56: 5 FAILED / 10 PASSED. Browser and an independent
  RFC4180 single-row path silently discarded some source spaces and
  sometimes treated illegal padded quotes as valid CSV.
- Already-qualified independent quoted-CSV source observer had a bounded
  readCells lexer that retained exact offsets. That source parser was
  extracted to shared src/csvSourceCells.ts, generalized only for explicit
  comma/semicolon/TAB selection; it was not duplicated.
- The browser tokenizeCSV and reviewed parseRfc4180SingleDataRow now
  reuse that scanner. The single record and source observer have consistent
  strict quotes/spacing while preserving original field values byte-for-byte.
- The independent observer continues REVIEW_ONLY_NAMED, never source/native
  auto-certification. When explicitly configured, it distinguishes a null
  unquoted empty from a quoted empty string; the default browser preview
  renders both empty strings until the user supplies a source schema.
- Semicolon/TAB remain explicit additional browser dialects and are NOT
  promoted as part of RFC 4180's comma-only grammar.

An older browser test expected liberal whitespace trimming around quoted
cells. It now verifies this pattern is not strictly RFC 4180, while a
correct strictly quoted row parses and preserves unquoted field-edge spaces.
This is an intentional standards-policy change in a non-product PoC.

### Pre-existing alternate padded-quoted source variant preserved

The historical independent unlabeled security-CSV candidate also supported
records whose quoted cells have an explicit space after the comma. That
syntax is not RFC4180; rejecting it globally would unnecessarily regress
a separately constrained legacy transport interpretation. The shared
csvSourceCells.ts scanner therefore has an *opt-in* delimiter-padding
parameter (default false). Only the existing bounded, strongly validated
standaloneUnlabeledCsv source candidate may invoke it after the strict
candidate fails, and only after its timestamp, all-quoted-field and shape
gates qualify the record. It labels this distinct outcome as
quoted_csv_unlabeled_padded_dialect and preserves the full original bytes.
This does NOT weaken generic RFC4180 browser parsing or claim that padded
cells have a universal original-source/native meaning. Other malformed or
arbitrary CSV/prose records remain rejected.

## Acceptance boundaries

- Frozen 14 source outcomes, field name/value/UTF-8 start/end exact replay,
  and malformed record abstention checked by focused tests.
- Full regression, TypeScript/Vite, previous safety replay and Exact-HEAD
  GitHub CI require actual green evidence rather than assumptions.
- 1,361 previously known originals, 2,892 mutated-invalid cases
  (including 197 REVIEW_ONLY) and prior 50 independent source samples
  stay safety-only; they are not an independent new accuracy lift.
- True relay boundaries, multiline CSV, custom declared manufacturer
  column names, quote/empty semantics across native Stellar/Fluentd, and
  other standards dialects remain incomplete and cannot be auto-promoted.

## Reproduction

    python3 scripts/poc/freezeStdCsvWhitespaceSource.py
    npx --no-install vitest run src/poc/standardCsvWhitespaceSourceParity.test.ts
    npm test
    npm run build
    git diff --check
