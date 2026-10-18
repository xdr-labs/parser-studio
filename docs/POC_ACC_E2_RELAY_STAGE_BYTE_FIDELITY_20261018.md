# ACC-E2 — Generic Original-Stage vs Collector-Stage Byte Fidelity

## Authority, scope and non-promotion boundary

This is an isolated source-evidence PoC stacked on Draft PR #83 exact HEAD
`47480169bb7e2a5fdee59eb25f767a3aa8fde41d`. It does **not** modify
product, main, native Fluentd/Stellar, sensor, DP, production, authentication,
deployments, or existing frontend/backend WIP.

ACC-E2 needs genuine original producer wire bytes matched to the corresponding
forwarder/collector wire bytes and independently authored expected field
names, decoded/typed values, and absolute original UTF-8 byte intervals.
A source parser can correctly decode *collector-visible* bytes even when a
forwarder has dropped producer bytes. A syntactically complete collector
message does **not** establish original device-event completeness.

The previous generic nested-Syslog observer
`src/poc/standardRelayProvenanceReview.ts` checks an embedded inner Syslog
record against a separate alleged upstream source. It deliberately does not
compare arbitrary separate before/after byte-stage pairs. This PoC covers
that distinct, non-nested case without adding vendor-specific regexes.

## Newly discovered public original-vs-receiver report — limited truth

The third-party reporter's syslog-ng/syslog-ng issue #2532
(https://github.com/syslog-ng/syslog-ng/issues/2532) provides a generator
script, sender/relay/receiver configuration and *displayed* before/after
message lines. The reporter lists syslog-ng 3.8.1 and Debian/Raspbian 9.
The sender program concatenates deterministic ASCII content.

Frozen on dev-atlas, not committed or redistributed:
`~/.local/state/parserstudio-acc-e2-syslogng-reporter-20261018`,
with restrictive 0700 directory / 0600 source permissions. The downloaded
GitHub API body text SHA256 is
`18607e16472b1adbe8cfb2f84f8a73890ccab7c744390b7cb51f27e17ace8b71`.

Independent reproduction from the published Perl generator matches the
reported producer text exactly: 1,045 bytes, SHA256
`8f7959d0ead7d6061a1cbef928194debf757f5cd91c451e4c1b6f6dd53507ef4`.

The two reporter-visible alternatives are:

| Displayed path | Source bytes | Receiver displayed bytes | Exact common prefix | Stage-local difference |
| --- | ---: | ---: | ---: | --- |
| UDP without source spoofing | 1,045 | 1,046 | 1,045 | One trailing space in **displayed text** |
| UDP with `spoof-source(yes)` | 1,045 | 921 | 921 | Source bytes **[921, 1045)** not present in displayed receiver suffix |

The single trailing space may have been inserted by a receiver log template
or the reporter's presentation, rather than on the transport wire. Similarly,
these are reported text strings, **not** packet captures. They demonstrate
bounded original/receiver *displayed-text* difference under the reporter's
configuration, **not manufacturer-authenticated direct device wire loss**,
device-origin identity, exact transport peer, source clock, or independently
typed manufacturer-field correctness. These two examples are not a new
device-wire TP/FP/FN denominator. None of the original manufacturer ACC-E4
197 REVIEW_ONLY cases are eligible for promotion.

## Shared source-stage byte observer

`src/poc/accE2RelayPairByteFidelity.ts` accepts each stage as raw
`Uint8Array` plus a required SHA-256 pin. It performs bounded
(1 MiB per stage) **byte comparisons** before any decoder, regardless of
opaque or malformed UTF-8. Stage counts and strictly stage-local half-open
byte spans are returned; the original source never gets reconstructed from
missing data.

A pinned pair can be marked review-only as exact byte equality, collector
strict prefix, collector append-only, or non-prefix byte difference.
Unpinned/altered/empty/oversized inputs abstain. Missing upstream evidence
is explicitly `REVIEW_ONLY_NO_UPSTREAM_PAIR`. No generic parser or
manufacturer-specific escape behavior is altered. The observer cannot infer
a single physical event correlation, firmware/output mode, relay clock,
source identity, TLS peer or actual missing field values.

**Even exact equality stays review-only.** Every result has
`originalDeviceIdentity:NOT_ATTESTED`,
`transportPeerAuthentication:NOT_VERIFIED`,
`eventClockOrdering:UNSCORABLE`,
`sourceComplete:false`, `nativeVerified:false` and
`canAutoPromote:false`. A hash proves byte integrity, not device identity.
The code does not emit or log private raw source payloads.

## Independently pinned verification and restrictions

- `scripts/poc/freezeAccE2RelayPairByteOracle.py` froze **12 independently
  authored synthetic byte pairs before candidate implementation**, including
  UTF-8, binary, mid-codepoint truncation, equality, strict prefixes,
  append-only and arbitrary changes. Fixture SHA256
  `dae28a946cd0f0f951ca60a45734f1772e7a8d297ce92a1eefd08d1ab5054830`.
- The newly authored source-only tests first failed RED (missing implementation),
  then passed GREEN **15/15**. The fixture is synthetic structural evidence,
  **not** real device traffic or a new manufacturer field/UTF-8 oracle.
- Private reporter text replay:
  `scripts/poc/replayAccE2PublicReporter.ts`, **2/2 reported text-stage
  observations** reproduce prefix/added/lost intervals without promotion.
  The private raw data are never copied to GitHub or CI.
- Full deterministic tests, build, historical 1,361 originals + 2,892
  invalid mutations including 197 REVIEW_ONLY, and Exact-HEAD CI remain
  separate and must be observed before declaring the PoC qualified.
- New manufacturer-wire score remains **UNSCORABLE, denominator 0**,
  not 0%-accuracy. Actual attested producer/relay PCAPs/configuration and
  independent typed-value/UTF-8 intervals are still needed.

## Reproduction

```sh
python3 scripts/poc/freezeAccE2RelayPairByteOracle.py
sha256sum scripts/poc/accE2RelayPairByteOracle.pinned.json
npx --no-install vitest run src/poc/accE2RelayPairByteFidelity.test.ts
./node_modules/.bin/vite-node scripts/poc/replayAccE2PublicReporter.ts # dev-atlas private only
npm test
npm run build
npx --no-install vite-node scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install vite-node scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install vite-node scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
```

This PoC is evidence-only and remains in an isolated Draft PR. It does not
authorize native/product integration, actual device access, redistribution of
third-party raw logs, or PR merge.

## Completed local qualification (2026-10-18)

The independently authored generic 12-case oracle was first frozen before
implementing the candidate. Only its non-English sample payload literals were
replaced with English-plus-emoji equivalents before final qualification to
respect the repository language policy; the byte-stage expected classifications,
negative gates and fixture count were unchanged. The **final pinned fixture
SHA256** is
`dae28a946cd0f0f951ca60a45734f1772e7a8d297ce92a1eefd08d1ab5054830`.

- `npm run typecheck`: PASS.
- `npm test`: **215 files, 1,701/1,701 PASS**, including 15 new generic
  byte-stage tests.
- `npm run build`: PASS (ordinary Vite chunk-size advisory only).
- Post-adjustment focused generic/English-only tests: **18/18 PASS**.
- Private, reporter-displayed stage pair replay: **2/2** exact metadata
  comparisons without any device-wire/native promotion.
- Historical quoted CSV source safety: **1,361 originals + 2,892 invalids**,
  197 prior REVIEW_ONLY unchanged, zero source result/UTF-8 byte drift,
  invalid review promotion, auto promotion, VETO escape or excessive branches.
- Historical invalid mutation audit: 2,892; REVIEW_ONLY exactly 197
  (171 Sophos-shaped KV lexical, 26 RFC3164 envelope-only).
- Independent NonJSON historical safety: 1,361 originals, 2,892 invalids,
  zero new claims/review changes, zero auto promotion, UTF-8 drift or VETO escape.

Local verification is independent of GitHub Exact-HEAD CI; draft/CI
qualification must use the pushed commit SHA and the actual Actions result.
No blind new manufacturer accuracy denominator or native runtime claim follows.
