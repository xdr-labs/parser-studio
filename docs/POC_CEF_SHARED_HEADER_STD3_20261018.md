# P0-STD-3 — Shared CEF header grammar / browser false-complete guard

## Isolation and normative basis

An isolated standards/source audit branch based on qualified Draft PR #56
exact HEAD 2335895dbf8c9f3c6f67c1ff8b468f2a8f9f20e6.
No modifications to product/main, PR #51, PR #56, RFC5424 PR #57/#58,
pre-existing dirty worktrees, native targets, DP, sensors, credentials,
deployment, release or merge.

Primary vendor-authored *format* specification (not device capture):
- ArcSight CEF Implementation Standard v26:
  https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm
- SIEM CEF Implementation Standard v27 (2025):
  https://docs.microfocus.com/doc/2097/25.4/siemcefimplementationstandard

Both describe seven required nonempty CEF header components, escaped header
pipes/backslashes, and valid numeric 0–10 or named severity. The format's
extension remains separately parsed; its complete source span/native
semantics were not certified here. The v27 review addresses the prior
audit's open v26/v27 revision-reconciliation risk for this narrow header
contract, not all version differences.

## Immutable independently authored normative answer

Freeze before any implementation scoring:
- generator: scripts/poc/freezeStdCefHeaderParity.py
- oracle: scripts/poc/standardCefHeaderParity.pinned.json
- SHA-256: b898bf634b5d4e82676b17c799778c8f0ea5f187c449e70f325269483f1ec0fe
- 13 synthetic standards-derived records: 6 valid, 7 intentionally invalid.
- Exact ordered header name, source lexeme, decoded value, and absolute UTF-8
  byte start/end precomputed independently from authored input; the tests
  replay all original raw bytes. Samples are **not independent publisher-
  captured wire events**, producer/relay clock goldens or native artifacts.

Positive controls include non-ASCII vendor, escaped pipe/backslash, all
named and edge numeric severities, empty optional extension.
Negative controls include blank vendor/event name/severity, severity 99,
unsupported CEF version, unknown header escape and truncated separators.

## Demonstrated RED -> GREEN

On unchanged PR #56, new audit test: 5 FAIL / 9 PASS, because the browser
silently accepted five malformed standard headers, despite the independent
source-only header audit already abstaining on them.

Minimal generic correction:
- New pure shared grammar src/cefStandardHeaderGrammar.ts, returning
  ordered decoded fields, original lexical strings, absolute UTF-8 offsets,
  and precise extension-start cursor.
- Existing browser extractStructuredFamily(..., 'cef') invokes that grammar
  before claiming a parsed header; existing extension parsing unchanged.
- Existing isolated source-only standardCefHeaderAudit.ts now calls the
  same scanner instead of maintaining a second, divergent header parser.
- Malformed header cases produce browser errors and source ABSTAIN_UNSAFE,
  **not false-complete success**. Valid cases remain source REVIEW_ONLY_HEADER,
  never complete event/native-certified.

No vendor-specific regex, no CEF body/transport/native certification and no
new publisher field-accuracy claim. Source-byte observer for complex CEF
extensions still correctly abstains where independently unqualified.

## Acceptance evidence

- Independently frozen 13/13 narrow CEF header outcomes PASS.
- Focused CEF/LEEF/structured scenarios: 40/40 PASS.
- Whole Vitest 187 files / 1,258 tests PASS.
- TypeScript/Vite build, historical replay and exact-HEAD CI are separate
  required gates; record only their observed successful results.
- Historical safety replay denominators: 1,361 original records, 2,892
  mutated-invalid (including 197 REVIEW_ONLY), and 50 prior independently
  sourced cases. They are never relabeled new CEF accuracy gain.

Remaining P0-STD-3 source extension/native and cross-format negative
qualification, STD-4 LEEF format/byte-span parity and STD-5..11 are open.

## Reproduce

    python3 scripts/poc/freezeStdCefHeaderParity.py
    npx --no-install vitest run src/poc/standardCefSharedHeaderParity.test.ts
    npm test
    npm run build
    git diff --check
