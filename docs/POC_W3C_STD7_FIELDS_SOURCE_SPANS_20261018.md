# P0-STD-7 — W3C Extended Log File declared fields / source UTF-8 spans

## Normative authority and product-subset boundary

W3C Extended Log File Format, Working Draft (not a W3C Recommendation):
https://www.w3.org/TR/logfile/

The draft defines #Fields source names, whitespace-delimited entries,
double-quoted strings and doubled interior double quotes. No generic
backslash escape decoding is defined. The '-' sentinel denotes an
omitted field, which this source-observation lane keeps literal.
The draft specifies ASCII and CR/CRLF; Parser Studio separately
accepts bounded LF and UTF-8 IIS/CloudFront variants. Such supported
variants are explicitly compatibility subsets, NOT certified general
W3C conformance.

This isolated PoC is based on Draft PR #56 exact
2335895dbf8c9f3c6f67c1ff8b468f2a8f9f20e6 and does not
modify product/main, other Draft PRs or intentionally dirty worktrees,
native targets, DP, sensors, deployments or release state.

## Independently frozen test truths

Before scoring or changing the candidate source:
- generator: scripts/poc/freezeStdW3cFieldsAndSpans.py
- case answer: scripts/poc/standardsW3cFieldsAndSpans.pinned.json
- SHA-256: fed289f4d21e22109121875b3d0b5ec6afa470fb9018621a26d8db4b25327071
- 15 synthetic cases: 7 narrowly valid W3C/IIS/CloudFront-style
  single-schema row sets, 8 malformed or out-of-subset negatives.

The generator fixes literal original physical rows, source field names,
raw lexical spans, decoded value expectations, absolute source UTF-8
byte start/end, and full record count before candidate scoring.
It covers quoted spaces, doubled quotes, literal backslash, tab rows,
CRLF, multi-row boundaries and an explicitly non-normative UTF-8
source-offset compatibility case. Negative controls cover ambiguous
quote boundaries, control bytes, unsupported mixed row delimiters,
cardinality failures and unsafely changed schema without a new block.

These tests are independently authored synthetics, NOT publisher-captured
device logs, native Fluentd/Stellar goldens or whole-event FP/FN proof.

## RED -> GREEN generic grammar changes

- The previously unchanged W3C browser/source block exhibited nine RED
  outcomes in the frozen fixture: seven valid observations lacked exact
  field offset evidence and two malformed strings/control-byte cases
  were falsely accepted. Existing single-schema positives with ordinary
  quotes already parsed.
- Existing src/w3cTabular.ts now uses ONE bounded W3C row scanner for
  direct mapping and original-source span generation. It decodes
  doubled quote syntax from the W3C draft and preserves backslashes
  literally rather than applying an undocumented producer escape.
- The block scanner retains physical source offsets across LF/CRLF
  normalization and verifies each field is replayable from the
  exact UTF-8 received source. Explicit rowFieldSpans/sourceBytes/
  physicalLines are evidence fields, not automatic native certification.
- Invalid or otherwise unsupported ambiguous quotations/control
  bytes remain rejected. Header rotation across physical blocks and
  producer-specific null/empty semantics require explicit source
  evidence and separate scope, not silent success.
- Existing observed IIS/CloudFront scenarios are retained unchanged,
  without implementing manufacturer-specific regular expressions.

## Acceptance and unfinished scope

- Focused authored 15/15 plus existing W3C suites: 22/22 PASS.
- Full Vitest, TS/Vite build, historical safety and exact-HEAD GitHub
  CI are independent mandatory gates, not inferred from focused PASS.
- Historical replay: 1,361 originals, 2,892 mutated invalid
  (197 REVIEW_ONLY) and prior independent 50 remain safety only.
- Field meanings, authoritative source-vs-relay timestamps, complete
  event/native target, publisher-original accuracy, W3C directive
  rotation and STD-8..11 remain unqualified.

## Reproduction

    python3 scripts/poc/freezeStdW3cFieldsAndSpans.py
    npx --no-install vitest run src/poc/standardW3cFieldsAndSpans.test.ts
    npm test
    npm run build
    git diff --check
