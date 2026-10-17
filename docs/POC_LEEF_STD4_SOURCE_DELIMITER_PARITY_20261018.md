# P0-STD-4 — LEEF 2.0 declared delimiter / source UTF-8 parity

## Primary format contract

IBM official LEEF event components:
https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components

LEEF 2.0 may declare exactly one literal delimiter character or a
hexadecimal 1..4 digit Unicode code point prefixed by x or 0x. LEEF 1.0
defaults to a TAB between event attributes. Browser/source observers must
interpret the *declared delimiter*, not search only for vendor-specific
characters. Invalid, ambiguous or control delimiters remain unsupported.

Isolated source/browser-only branch based on Draft PR #56 exact
2335895dbf8c9f3c6f67c1ff8b468f2a8f9f20e6.
No product/main/PR #51/#56/#57/#58/#59, dirty frontend/backend, target,
DP/sensor, credential, release, deployment or PR-merge modifications.

## Frozen independent authored normative expectations

The authored expected field values and exact UTF-8 byte positions were
generated/frozen **before** running the candidate:
- generator: scripts/poc/freezeStdLeefDelimiterParity.py
- answer: scripts/poc/standardsLeefDelimiterParity.pinned.json
- SHA-256: 4a30628234e4c5c681fdc73ed2f4215f810d2bf5d094d76503a3af0d65ddb00a
- 14 independent *synthetic* format-rule controls: 8 valid and 6 invalid.

Positive cases cover x5E, 0x5E, xa6, literal Unicode U+00A6,
x09, 0x09, 0x3A, and LEEF 1.0 default TAB. They include Unicode and
spaces in values. Six negative controls cover NUL, line-feed,
surrogate codepoint, malformed hex token, equals and backslash delimiters.

All expected ordered field identities, lexical UTF-8 byte offsets and
decoded literal values are computed independently from the original raw
wire string. These are **not** producer-authored log captures,
manufacturer-independent semantic goldens, or native Stellar tests.

## RED -> GREEN implementation

On the unchanged original source observer, new tests had **6 FAILED /
9 PASSED**, despite the browser already handling those valid cases.
The source observer intentionally abstained on unreviewed delimiters,
which protected raw data but reduced standards-format coverage.

A single pure shared function, src/leefStandardDelimiter.ts,
now validates and resolves the delimiter grammar. Existing browser
src/structuredFamilies.ts and source-only
src/poc/independentLeefSource.ts import it instead of maintaining
different delimiter interpretations. No new manufacturer regex or
duplicate field lexer. The source observer continues to report
REVIEW_ONLY_STRUCTURED_BODY rather than a complete or native-certified
event; its original UTF-8 byte interval claims are tested byte-for-byte.
Invalid controls still ABSTAIN_UNSAFE, with no source field promotions.

## Scope, unresolved claims and verification

The browser may reject duplicate LEEF attribute keys while the source
observer records separate lexical occurrences for review. This is an
explicit cross-surface semantics issue, NOT grounds for silently
reinterpreting duplicate keys. Unknown relay semantics, target-native
parser, manufacturer-specific event meanings and full-event FP/FN remain
UNSCORABLE until publisher/native independent answers are available.

- 14/14 frozen narrow normative expected outcomes.
- Focused browser/source LEEF/CEF tests: 49/49 PASS.
- Full Vitest, TypeScript/Vite build, historical safety replay and
  exact-HEAD GitHub CI require their separately observed final outcomes.
- Historical original 1,361, invalid 2,892 (197 REVIEW_ONLY) and prior
  independently sourced 50 are **safety replay**, never new accuracy data.

Remaining STD-1/2 genuine transport/relay/native, STD-3 extension
fidelity/native, STD-4 duplicate/empty key policy/native, and STD-5..11
general standards audit remain open.

## Reproduce

    python3 scripts/poc/freezeStdLeefDelimiterParity.py
    npx --no-install vitest run src/poc/standardLeefDelimiterParity.test.ts
    npm test
    npm run build
    git diff --check
