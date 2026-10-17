# P0-STD-1/2 — RFC 6587 Framing & RFC 5424 SD Cross-Surface Conformance

## Scope, sources and exact boundaries

Owner-selected highest-priority normative grammar audit, NOT manufacturer-by-
manufacturer corrections. This is an isolated source-only cross-surface audit,
branched from Draft PR #52 exact HEAD
`492964acf36594be02a6c10f14f43dfa1c90614a` in
`/home/aella/parser-studio-std-framing-sd-transfer-poc-20261018`.
The independent first P0-STD audit Draft PR #56 remains untouched.

**Authoritative normative sources:** RFC 6587 section 3.4 (transport framing,
Informational RFC), RFC 5424 sections 6 and 6.3.3 (SD-PARAM and escaping,
Standards Track). Exact standard reference byte SHA pins remain in Draft PR
#56 `scripts/poc/normativeGrammarSources.pinned.json` and private
`~/.local/state/parserstudio-p0-standards-audit-20261018`. No third-party
document text or customer logs are distributed.

The new synthetically authored standardized case set is frozen BEFORE this
PoC candidate scoring, SHA-256
`15f3d48772dc7b05ee0807c6801d6771efbcf454003feed9f8b2e9b74fed1b7d`,
at `scripts/poc/standardsFramingSdCases.pinned.json` (21 examples). These
fixtures express controlled format rules, **not** independently publisher-
authored device source goldens nor full event/native correctness.

## Measured source-stage results

| Conformance subset | Cases | Existing source parser |
| --- | ---: | --- |
| RFC 6587 octet-counting, UTF-8 byte lengths, two-record streams, truncation and incorrect octet counts | 5 | 5/5 expected narrow outcomes |
| RFC 6587 LF, CRLF, NUL, mixed delimiters, missing last record boundary and explicitly counted multiline MSG | 6 | 6/6 expected narrow outcomes |
| RFC 5424 SD-PARAM escaping, unknown escape preservation, repeated parameter names, multiple SD elements, NILVALUE, byte-offset replay | 6 | 6/6 expected narrow outcomes |
| RFC 5424 malformed controls: duplicate SD-ID, raw unescaped right bracket, invalid leap date, unterminated parameter quote | 4 | 4/4 correctly rejected |

**All 21/21 expected source-level outcomes matched** on this authored
standards-derived subset. Additional focused tests: **23/23 PASS**.
All octet-counted stream payload bytes and accepted structured-data raw
intervals were preserved in tests. No native, manufacturer-semantic, full-event
false-positive or field F1 success is inferred.

### Two format-conformance differences among implementation paths

1. **Unknown RFC 5424 SD backslash sequence.** Section 6.3.3 specifies that
   backslashes not followed by the defined escapable characters remain
   ordinary literal data. The byte-level `src/poc/rfc5424SdByteEscapes.ts`
   accepts the input and retains literal backslash; the browser-only
   `src/rfc5424Subset.ts` conservatively rejects it.
2. **Repeated RFC 5424 SD-PARAM.** RFC 5424 6.3.3 explicitly permits repeated
   SD-PARAM names *within* one SD-ELEMENT. The byte-level scanner retains
   ordered occurrences; the narrower browser subset rejects the repetition.
   The SD-ID itself is not allowed to repeat, and both refuse that case.

This is a potential **false-negative / portability gap**, not evidence that
a malformed event was silently accepted, nor that the product has no
RFC 5424 support. Avoid implementing a second redundant SD scanner:
the shared standard grammar should preserve escaped raw source regions,
decoded parameters and order while imposing browser/native compatibility
gates. Release/native claims require independent source and target evidence.

## Cross-format and transport safety rules upheld

- RFC 6587 counted transport is **byte-counted** rather than JavaScript
  UTF-16 length. A valid counted message may itself contain an LF without
  producing two records.
- Non-transparent delimiters must be correctly terminated. Mixed/ambiguous
  delimiters, bad counts, truncated payloads and counted mid-UTF8 corruption
  cannot silently become complete records.
- RFC 5424 SD escaping must never leak into MSG or CEF/LEEF extension
  semantics; unknown escapes are preserved rather than guessed.
- Duplicate SD-PARAM values are preserved in order, unlike an overwriting map;
  duplicate SD-IDs remain invalid under RFC 5424.
- Absolute UTF-8 intervals always address the received raw bytes; decoded
  values must never shift source boundaries.
- All results are source-stage bounded evidence, never manufacturer-wire/native
  Stellar proof.

## Remaining work and precise acceptance

STD-1 paired genuine direct/forwarded vendor source bytes, relay hop attribution,
transport security/TLS/native buffer and truncation; STD-2 browser/source/native
parity for all RFC 5424 HEADER/STRUCTURED-DATA variants, MSG multi-line, full
timestamp and NILVALUE policy. Independent original-author field name, decoded
value and exact byte goldens, alongside manufacturer negatives, must be pinned
before scoring. The 1,361 historical originals, 2,892 mutated invalids and 197
lexical REVIEW_ONLY remain *safety only*; the prior 50 external source cases
remain a separate regression set.

No qualified Multi-Pass/Funnel, product/main, existing PRs, dirty frontend/
backend worktrees, native Fluentd/Stellar target, DP/sensors, credentials,
production, deployment, release or merge changes are authorized.

## Reproduction (isolated branch)

```sh
python3 scripts/poc/freezeStdFramingSdCases.py
npx --no-install tsx scripts/poc/scoreStdFramingSd.ts
npx --no-install vitest run src/poc/standardFramingSdTransfer.test.ts
npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
npm test
npm run build
git diff --check
```

Only independently demonstrated source grammar improvements may become
portable parsing behavior. This source-only evidence should be a Draft PR
with full exact-head GitHub quality CI including Chromium and pinned
localhost backend HTTP integration, **not a production/native promotion**.
