# P0-STD-3 — Shared CEF Extension source grammar with original bytes

## Authority and scope

ArcSight/Micro Focus official Common Event Format Implementation
Standard, publisher-owned v26 HTML:
https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm

Immutable original HTML SHA-256:
e5403a0362d8534af933c3038d15c4b847c70d9fab75a282f91097e27489a994

From that document, four complete publisher-authored one-line examples
explicitly illustrate (1) escaped header pipe + spaced extension value,
(2) escaped header/extension backslash, (3) escaped extension equals
and (4) encoded extension newline. Exact publisher source examples
are retained ONLY under mode 0600 files / mode 0700 directory on
dev-atlas, never committed or sent to third-party AI services.

The default browser and independent source observer must agree on
CEF's generic lexical encoding rules. A browser grammar match is
NOT a fully verified producer field value or native Parser Studio
target match. This isolated source-only branch is based exclusively
on qualified P0-STD-9 official CEF original PoC Draft PR #69 exact
f9542b0bd3f6404de57ab68de0686c318390639a.
Product/main, other Draft PRs and intentionally dirty frontend/backend,
DP/sensors, native target, deployments, release and merge are unchanged.

## Independent pre-frozen publisher ground truth

Original **source SHA and field-value-interval oracle were frozen
BEFORE parser scoring or the new common scanner was implemented**:

- Generator: scripts/poc/freezeStdCefPublisherEscapes.py
- Digest-only expected answers:
  scripts/poc/standardCefPublisherEscapes.pinned.json
- Immutable fixture SHA-256:
  ec43bbf61e211e693cff40ce813a289863743396a64b164194cfc65fe16f7309
- Four independent *publisher-written standards illustrations*, not
  production device captures or blind manufacturer tests.
- 39 independently ordered source field claims total:
  seven required headers per row, and three/two CEF Extension keys.
- Every claim includes original byte offsets, original lexeme hash,
  expected decoded value hash, field name and occurrence ordinal.
  The original source is scored only by comparing with the protected
  exact publisher bytes and their SHA. No parser output builds the
  expected oracle. Copyright-sensitive example logs never enter Git.

## RED -> GREEN

On the unmodified qualified PR #69 original source observer, all four
official publisher examples failed full source-field fidelity:
- expected source claims 39;
- exact source-observer plus browser/pipeline matches TP=0, FN=39;
- source observer had 14 incompatible partial claims;
- the existing browser and full Syslog+CEF pipeline each decoded all
  four examples at the browser level, but their source-observer
  raw-byte contract was inconsistent. No native success was claimed.

The generic structural improvement:

1. New bounded src/cefStandardExtensionGrammar.ts shared by the
   browser and independent source observer, not a new vendor regex.
   It distinguishes original extension raw lexical values and
   decoded values while accounting for escaped backslash, equals,
   newline, carriage-return and unknown literals exactly as the
   existing CEF browser interpretation. It preserves the original
   UTF-8 byte interval and rejects unmatched physical record controls,
   source bounds exhaustion, unsafe keys and truncated escapes.
2. Source CEF header extraction now uses the already-qualified shared
   src/cefStandardHeaderGrammar.ts rather than a second scanner that
   incorrectly rejected valid escaped pipes/backslashes.
3. The browser CEF Extension extracts decoded field values from that
   one same lexical scanner. Source review preserves duplicated keys
   in original occurrence order, while the browser declines unsafe
   duplicate-key map overwrite.
4. An apparent key boundary located within producer-unqualified
   quote-looking text is NOT interpreted as a second supported field;
   both interfaces reject/review that ambiguous source. Field/value
   quotations are never silently normalized as a vendor-specific
   quoted KV dialect.
5. An empty extension value retains its original raw source; Native
   null/absent typing remains UNSCORABLE without a producer contract.
6. The source observer STILL returns REVIEW_ONLY_STRUCTURED_BODY,
   cannot auto-promote, and never claims native parser validation.

Post-change score on the same privately frozen publisher originals:
- **4/4 publisher illustrative examples exact**;
- **39/39 ordered field identity, decoded value and original UTF-8
  byte start/end exact**; TP=39, FP=0, FN=0, byte drift=0;
- browser and full original Syslog+CEF pipeline matched the same
  4/4 publisher-example field sets;
- source auto promotions 0, nativeVerified false.

These metrics are for FOUR PUBLIC PUBLISHER EXAMPLE MESSAGES ONLY.
They must never be described as real manufacturer operational logs,
all-firmware CEF accuracy, a new vendor-specific regex gain,
unseen blind holdout, or Native Stellar/Fluentd exact-event F1.

## Separate authored regression / remaining limitations

The public-CI-safe source tests exercise 11 extra authored synthetic
structural cases for spaces, literal unknown escapes, declared escapes,
UTF-8 after multibyte headers, repeated source keys, empty source
values, CEF field spacing, control bytes, source bounds and ambiguity.
These authored cases are NOT additional publisher goldens and not
new independently sourced field F1.

Existing 1,361 original / 2,892 mutated-invalid historical cases
(including 197 REVIEW_ONLY) and earlier independent 50 cases remain
regression safety only, not newly scored manufacturer accuracy.
Unverified producer profile semantics, CEF double-quoted value
heuristics, source-vs-forwarder time/host attribution, unknown real
device variants, external native target and product mapping remain
PARTIAL, REVIEW_ONLY or UNSCORABLE.

Full Vitest/TypeScript/Vite, safety replay, separate Chromium browser
tests and exact-head CI must independently PASS before accepting
this source-only candidate. No product/production or PR merge.

## Reproduction

    python3 scripts/poc/freezeStdCefPublisherEscapes.py
    npx --no-install vitest run src/poc/standardCefExtensionSourceParity.test.ts
    # Only on dev-atlas with the protected publisher originals:
    npx --no-install tsx scripts/poc/scoreStdCefPublisherEscapes.ts
    npm test
    npm run build
    git diff --check
