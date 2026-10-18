# ACC-E5 — Generic bounded colon-label source excerpt fidelity

## Evidence provenance and architectural objective

This isolated source-only PoC is based on qualified Draft PR #85 exact
`33995fb835e18a5b56c0e95fadeff5203a19fba4`. It is **not** a native
product/DP integration and never asserts a complete event, physical device,
manufacturer firmware, relay transport, or authoritative typed field meanings.

The general `Label: Value, Label: Value` grammar occurs in multiple security
logs and Syslog message bodies; this PoC does not contain a Cisco-specific
regex or any vendor fallback. Existing
`src/genericStructural.ts` already includes a bounded
`commaLabelValueBody` helper for *qualified Syslog envelopes*, but its
source-independent map does not establish the exact byte positions of an
unframed, truncated or concatenated collector message. A default structural
parse MUST NOT interpret unqualified record boundaries as event success.

The new `src/poc/accE5PartialColonSource.ts` accepts **only a caller-declared
original byte interval**, not guessed source/relay framing:

- SHA-256 of the full original `Uint8Array`, range `[startByte,endByte)`,
  and independently pinned SHA-256 of that range.
- An explicit source-slice-only scope marker. Unasserted scope remains
  `RAW_ONLY`.
- A bounded (64 KiB original / 16 KiB excerpt / up to 128 occurrences)
  generic comma+space-separated `Name: Value` grammar.
- Every name, original *lexical* value and ordered occurrence is replayed
  from half-open **original UTF-8 byte spans**. A colon inside a value is
  ordinary literal source text; it does not introduce a second field.
- Ambiguous comma/quote escaping, missing delimiter, incorrect source
  hash, mid-character boundary, hidden delimited field in the prefix,
  invalid source controls, malformed value and over-budget inputs fail
  closed. No missing value is fabricated.
- The entire original bytes remain available to the caller. Output provides
  the source interval **and** counts of unreviewed bytes before and after
  it; this PoC never silently discards residual bytes.

**No successful native or physical event claim follows.** All outputs
retain `sourceComplete:false`, `nativeVerified:false`,
`independentOracleCertified:false`, `canAutoPromote:false`,
`manufacturerSemantics:NOT_CERTIFIED`,
`originalDeviceIdentity:NOT_ATTESTED` and
`transportPeerAuthentication:NOT_VERIFIED`. A caller-selected region is
an *assertion*, not proof that the remaining bytes are a separate event.
The code does not emit private original messages.

## Primary real collector-text negative: Cisco FTD report

The third-party [Elastic integrations issue #15204](https://github.com/elastic/integrations/issues/15204)
contains an `event.original` collector text alleging a Cisco FTD
`%FTD-6-430003` message. It is **not a device-wire PCAP or a bounded
native field oracle**. Its source original was already privately frozen
before this new PoC.

- Reported full source: **1,154 UTF-8 bytes**, SHA-256
  `5bcaa76adeb3e286b8ca97a4b3f3a9b1f6ed13d4334efadd26a384b7a4dab7fe`.
- An independently written private Python scanner froze **31 complete**
  label/value source claims *before* creating the TypeScript candidate,
  using only literal `Name: Value` segments and exact original byte spans.
  Private Oracle SHA-256
  `9d9287bc2854ef776bb920d003765aea69ed1ab2a471ae7da3a9091edb213ecf`.
- Explicit source review excerpt `[49,959)`; the **unreviewed 195-byte
  suffix** begins with an unfinished `ResponderB` field and contains an
  embedded second Syslog PRI marker at byte **971**.
- Existing Generic Structural declined to claim the fused event as
  a complete source parse. The new observer independently matched the
  frozen **31/31 field names, raw values and original byte offsets**,
  while keeping all 195 residual source bytes unscored and
  `sourceComplete:false`. It does **not** segment the two purported
  messages, deduce whether bytes were lost in transit, or infer absent
  values.
- Official [Cisco Secure Firewall FTD security-event documentation](https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/fptd_syslog_guide/security-event-syslog-messages.html)
  says that starting in release 6.3 empty or unknown fields are omitted
  from security-event syslog messages. Therefore a missing observed label
  must not be invented as an empty field; physical producer configuration
  and actual wire confirmation are still required to apply this rule to
  a particular event.

Private source and pre-candidate expected byte ranges:
`~/.local/state/parserstudio-acc-e3-public-negative-review-20261018`
and `~/.local/state/parserstudio-acc-e5-cisco-ftd-partial-source-20261018`
on dev-atlas; no raw event or expected values are committed to GitHub.

## Independent synthetic RED → GREEN

Before authoring the candidate module,
`scripts/poc/freezeAccE5PartialColonOracle.py` independently authored
34 synthetic case outcomes (10 valid, 24 unsafe/negative) and
**30 original-byte claims** with frozen fixture SHA-256
`6f0e97d948ea0b04dc7609e0cbbb64a816bd2d8ff8aa1c38c7af1700689e4a94`.

The immutable source cases cover non-vendor metadata prefixes, value
colons, ordered repeated literal labels, UTF-8 supplementary characters,
literal numbers/boolean-looking values, truncated suffixes, exact end-of-input
and explicit source-slice review. Negative cases reject false source/prefix
hashes, illegal controls/binary data, surrogate-boundary truncation,
unknown comma/quote policy, unsupported anonymous fragments, incompletely
framed fragments, source hiding and unsafe resource bounds.

New focused `src/poc/accE5PartialColonSource.test.ts` first failed RED
because the source gate was absent. After implementing the generic module,
**36/36 focused tests passed**, including independent fixture verification
and duplicate occurrence preservation.

## Required completion gates

Source-only evidence is not a substitute for transport/native proof.
Before recording a qualified Draft PR, run on the exact candidate:

1. Frozen synthetic oracle and focused 36 tests.
2. Private Cisco report comparison with 31 original-byte claims.
3. Full Vitest suite, TypeScript check and build.
4. Pinned 1,361 historical originals / 2,892 invalid mutations and
   existing 197 REVIEW_ONLY audit: no new auto promotion, source span drift,
   VETO bypass, or false-complete claim.
5. Exact pushed SHA and full GitHub Actions, including Chromium and real
   localhost backend HTTP integration, not merely green local tests.

All source-only PoC PRs stay DRAFT and UNMERGED. Preserve PR #83–#85,
the existing product worktree, frontend 11 and backend 10 dirty items,
main, native Fluentd/Stellar, production/DP/sensors, deployments and releases.

The next real manufacturer ACC-E1..E5 accuracy admission still requires
original physically attested producer wire bytes, exact firmware/output
settings, a matched before/after relay capture, separately authored
same-event typed field/value/UTF-8 interval expectations, plus negative
field controls. A third-party `event.original` string cannot supply them.

## Local reproduction

```sh
python3 scripts/poc/freezeAccE5PartialColonOracle.py
sha256sum scripts/poc/accE5PartialColonOracle.pinned.json
npx --no-install vitest run src/poc/accE5PartialColonSource.test.ts
./node_modules/.bin/vite-node scripts/poc/replayAccE5CiscoReportedPartial.ts # private dev-atlas only
npm run typecheck
npm test
npm run build
./node_modules/.bin/vite-node scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
./node_modules/.bin/vite-node scripts/poc/auditHistoricalMalformedReviewBounds.ts
./node_modules/.bin/vite-node scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
```

## Completed isolated local qualification — 2026-10-18

- Frozen independent authored fixture: SHA-256
  `6f0e97d948ea0b04dc7609e0cbbb64a816bd2d8ff8aa1c38c7af1700689e4a94`,
  34/34 expected outcomes and 30 bounded original-byte claims; tests
  **36/36 PASS**.
- Final focused source + English-only: **39/39 PASS**.
- Private previously frozen Cisco reporter source and Oracle:
  **31/31 original name/value/UTF-8-byte claims** on marked interval
  `[49,959)`, with the full 1,154-byte input retained and
  **195 unreviewed suffix bytes** explicitly recorded. This is a
  post-hoc partial source annotation, **not** a blind holdout,
  manufacturer-device packet capture or native typed-value certification.
- `npm run typecheck`: PASS.
- `npm test`: **217 Vitest files / 1,768 tests PASS**.
- `npm run build`: PASS (existing Vite large chunk advisory only).
- Historical 1,361 originals and 2,892 invalid source variations:
  source results, UTF-8 spans and original byte intervals unchanged;
  **197 prior REVIEW_ONLY** remain unchanged (171 Sophos-shaped KV,
  26 RFC3164 envelope-only); zero auto-promotion, VETO escape or
  newly claimed source fields. Historical corpus remains a known
  safety regression set, not a newly blind accuracy score.
- GitHub Draft PR Exact-HEAD CI is a separate mandatory gate. Native
  source-authenticated manufacturer device score remains 0 newly
  eligible events / UNSCORABLE.
