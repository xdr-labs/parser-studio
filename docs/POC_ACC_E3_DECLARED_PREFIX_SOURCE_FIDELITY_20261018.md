# ACC-E3 — Externally declared Prefix + generic source KV byte fidelity

## Goal and safety limits

This evidence-only PoC extends the source review boundary while preserving the
qualified Multi-Pass/Generic Structural/Funnel parser and the prior source-only
Draft PR #84 at exact HEAD
`851be0206f020db41de48b02da35744a16060fb5`. It implements **no**
vendor-detected regex, silent Syslog envelope/relay identity guess, parser
promotion, native Fluentd/Stellar adapter change, product UI integration or
main/production/deployment/DP/sensor action.

User-declared prefix markings are an owner-approved *future product authoring*
direction. The new `src/poc/accE3DeclaredPrefixSource.ts` is a narrow, pure
evidence observer only: a caller must provide a full original source byte
buffer, independently pinned SHA256 of that buffer, exact prefix end byte,
independently pinned prefix SHA256, explicit `space_kv` dialect and a claimed
`CONFIRMED_SINGLE_SOURCE_RECORD` boundary. Those are externally supplied
claims, **not** proof of physical capture, sender identity or native behavior.

It retains the entire original stream and marks only source-local lexical
claims with half-open original UTF-8 byte intervals. The existing bounded
`scanKeyValues` lexer and independent `replayCandidate` verify full token
consumption after the declared prefix; quote/escape handling is reused, not
inferred from vendor names. Repeated literal keys retain ordered occurrences
instead of being overwritten; the native meaning of a duplicate is **never
certified**.

The prefixes must end at a real ASCII space or tab, contain no hidden
`name=value` segment, and be bounded to 512 bytes. Explicit malformed PRI
inputs are ineligible for this fallback, so a failed RFC3164/RFC5424 header
cannot be bypassed by manually selecting a convenient prefix. Source is
bounded to 16 KiB and validated using fatal UTF-8 decoding and verified byte
offsets, including supplementary-plane Unicode. Malformed, binary, truncated,
unaccounted, mixed-format or unpinned sources **ABSTAIN**, never guessed
complete. With missing single-event framing, return `RAW_ONLY`.

All results retain:

- `autoPromoted:false`, `independentOracleCertified:false`,
  `sourceComplete:false`, `canDecodeVendorEscapes:false`
- `originalDeviceIdentity:NOT_ATTESTED`,
  `transportPeerAuthentication:NOT_VERIFIED`
- `manufacturerSemantics:NOT_CERTIFIED`,
  `nativeTarget:NOT_VERIFIED`

These are *reviewable native field lexemes*, not a successful native output
or a direct measurement of physical source-device accuracy.

## Frozen standards-authored independent synthetic proof

The independent Python script
`scripts/poc/freezeAccE3DeclaredPrefixOracle.py` was authored and
frozen **before** the candidate source module existed. Its fixture
`scripts/poc/accE3DeclaredPrefixOracle.pinned.json` has SHA256

`ef6268f4c9f9c3126731d308d5551e9aa85e1b783ef90b02bf04c7765f2f76ff`

The 29 cases include 10 valid producer-neutral source declarations with
31 exact name/value/original UTF-8 positions, and 19 independently authored
negative controls: absent record framing, source/prefix hash mismatch,
missing/mid-key/out-of-range prefix, hidden KV field, malformed pseudo-Syslog
PRI, UTF-8 corruption, illegal source newline, malformed quoting, unkeyed
segments, canonical key collision, incomplete source and resource bounds.

RED: unchanged PR #84 lacked this explicit context operator; new source
tests first failed import. GREEN: the new 31-case focused suite passed.
A repeated literal name remains a replayable **source occurrence** even
though the prior funnel intentionally withholds full semantic completeness
for duplicates.

The fixture establishes generic boundary correctness only; it is not any
customer/manufacturer device packet or blind open-world accuracy corpus.

## Publisher documentary source replay — not physical-device accuracy

The *pre-existing*, independently authored and privately frozen oracles
predate this PoC. Their original source bytes and source expected values
remain private, not committed or printed:

- Sophos SFOS 21.5 documentation,
  https://docs.sophos.com/nsg/sophos-firewall/21.5/syslog/index.html ;
  publisher HTML SHA256
  `1f9832074fc7a55081e6fa7a125d7e42fe59f9ce795b1f6a90b026b57549334c`,
  independent prior lexical Oracle SHA256
  `e1e416ccd930827ed58c71558e05173e19517b88523dfc4ef0b389f7a326dbe1`.
  Eight published, explicitly marked no-PRI RFC3164-like prefix records,
  initially `RAW_ONLY` at the strict source observer, contain **238**
  independently defined name/value/UTF-8 positions. With externally
  declared and individually SHA-pinned prefix boundaries they become
  `REVIEW_ONLY_DECLARED_PREFIX`: **238/238 exact**.
- Fortinet FortiOS 7.4.8 *extended logging* documentation,
  https://docs.fortinet.com/document/fortigate/7.4.8/fortios-log-message-reference/496081/enabling-extended-logging ;
  original published 1,007-byte example SHA256
  `fd1c486fff5ee9ef1b9f647508e67a845e25e13ac05742bd24cd2379455ce7a1`,
  pre-existing independent Oracle SHA256
  `a5dffc3b5e82c70a8750aed8e9ce77ce6b7c1f69e7d8f0af35796ab7655d0d93`.
  Explicit documentary `2: ` prefix bytes are preserved at [0,3);
  **45/45** original source lexemes/values/spans match.

Private exact prefix annotation manifest SHA256:
`c10c409aa49338680953fe429a70a41a3bbf93f7a9e47d6c59464fe174e4c0ba`.
It is **post-hoc**, because the boundary annotation was created after
the earlier Oracle assessment; do not call the 283/283 comparisons a new
independently held-out sample or a manufacturer/native accuracy F1.

The private replay `scripts/poc/replayAccE3DocumentaryPrefixSafety.ts`
requires all pinned source bytes, prior original field Oracles and prefix
hashes. It verified **9/9** published examples and **283/283** lexical
name/value/original byte intervals without any auto promotion.

## Compatibility and pending gate

Default `arbitrateSourceBody`, RFC3164/RFC5424 grammar and ordinary
product extraction are **unchanged**. The new inspector is an explicit
opt-in source PoC, not a production parsing fallback. No manufacturer
semantics, actual event completeness, originator TLS peer, firmware-specific
escapes or native target were certified. Historical source review-only
197 cases (171 Sophos-shaped KV lexical, 26 RFC3164 envelope-only) may
not be silently reclassified.

Before accepting this source-only PR, verify TypeScript, all deterministic
Vitest suites, Vite build, private publisher replay, historical pinned source
replays and the **exact pushed HEAD** GitHub Actions web/build/browser/HTTP CI.
All preexisting product, frontend 11 dirty, backend 10 dirty, other Draft
PRs and main must remain untouched.

### Reproduction

```sh
python3 scripts/poc/freezeAccE3DeclaredPrefixOracle.py
sha256sum scripts/poc/accE3DeclaredPrefixOracle.pinned.json
npx --no-install vitest run src/poc/accE3DeclaredPrefixSource.test.ts
# dev-atlas only, requires private publisher source/Oracles:
./node_modules/.bin/vite-node scripts/poc/replayAccE3DocumentaryPrefixSafety.ts
npm run typecheck
npm test
npm run build
./node_modules/.bin/vite-node scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
./node_modules/.bin/vite-node scripts/poc/auditHistoricalMalformedReviewBounds.ts
./node_modules/.bin/vite-node scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
```
