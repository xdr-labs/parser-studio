# P0-STD-79 — IBM LEEF Empty-Value Source Positions and Duplicate-Semantics Boundaries

## Authority and rules

IBM LEEF event components and the IBM QRadar custom-event-keys specification define delimiter-scoped event attributes. The latter notes that repeating the same key/value pair can cause QRadar to ignore a duplicate value. The normative materials do not by themselves establish firmware-specific meaning for a present empty value, nor guarantee uniform native handling of repeated keys.

Official sources:
- https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components
- https://www.ibm.com/docs/en/qsip/7.5.0?topic=overview-custom-event-keys
- https://www.ibm.com/docs/en/qsip/7.6.0?topic=keys-best-practices-guidelines-leef-events

## Root cross-surface defect and narrow correction

- Previous source-byte lexical observer src/poc/independentLeefSource.ts treated key= as malformed, while browser source parse in src/structuredFamilies.ts already accepted it as the empty string. This lost evidence about the **presence** of a key whose original raw value is exactly zero bytes. It did not prove that empty source values are manufacturer-null, absent, defaulted, or native-mapped.
- Extend the **existing generic LEEF source lexer**, not a separate vendor parser: permit zero-length extension raw slices, explicit half-open UTF-8 original intervals [startByte,endByte) with equality, and lexical decoded value "". Header fields stay nonempty. The browser rejects missing or entirely blank required header component values instead of producing an ungrounded LEEF success.
- LEEF 1.0 TAB and explicitly declared LEEF 2.0 separator rules are unchanged. Repeated source keys retain separate ordered original occurrence paths; the browser rejects duplicate extension names rather than silently overwriting. Source observation remains REVIEW_ONLY; no claim that QRadar will choose first, last, ignore, dedupe, or map an empty value to null.
- Incomplete body, malformed separators, unsafe names, ambiguous quoting, and wrong formats remain review or abstain. No new manufacturer-specific escapes or direct parser/native promotions.

## Synthetic oracle and verified scope

- Frozen, independently authored synthetics: scripts/poc/freezeStdLeefEmptySourceSemantics.py and scripts/poc/standardLeefEmptySourceSemantics.pinned.json, SHA256 **e6b0c14dddb51a67833009e9336c0351dc0558c0306c8b9f7cb69eb9d065918a**.
- Fifteen authored cases, nine strictly lexical source outcomes, nine empty literal value fields with half-open original byte intervals. Cases span LEEF 1.0 TAB, LEEF 2.0 caret and hex TAB, UTF-8 multibyte fields, repeated identical/empty keys, unqualified quoted value, blank header, missing =, trailing delimiter, reserved names.
- Pre-fix RED: **10** failed expectations on duplicated/empty/header parity. Narrow fix GREEN: three focused suites **46/46 PASS**. Full regression, TypeScript/Vite, historical safety and exact-head GitHub CI require individually observed outcomes.
- The zero-length source span is source-stage truth for a lexical zero-length value, NOT a device/QRadar/Stellar semantic proof or full-event score. Historical 1,361 originals, 2,892 mutations (197 REVIEW_ONLY), previous independent material remain **historical safety only**.

## Isolation and remaining evidence

Source-only isolation is based on Draft PR #78 exact HEAD 66c234c6b83800cc9870869690fb254b7951ab67. Product/main, dirty frontend/backend, native Fluentd/Stellar, actual devices, DP, sensors, production, deployment, releases and unrelated PRs remain untouched.

To determine manufacturer-native empty/duplicate semantics one still needs a firmware-scoped independent producer document or original producer/collector/native triple evidence for those specific fields and known negative cases. In the absence of that evidence retain lexical review and abstention; do not invent normalization rules.

## Reproduction

~~~sh
python3 scripts/poc/freezeStdLeefEmptySourceSemantics.py
sha256sum scripts/poc/standardLeefEmptySourceSemantics.pinned.json
npx --no-install vitest run src/poc/standardLeefEmptySourceSemantics.test.ts src/poc/independentLeefSource.test.ts src/poc/standardLeefDelimiterParity.test.ts
npm test
npm run build
npx --no-install tsx scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install tsx scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install tsx scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
~~~
