# P0-STD-2 — RFC5424 VERSION 1 and TIME-SECFRAC exact grammar

## Primary published standard authority

RFC 5424 (https://www.rfc-editor.org/rfc/rfc5424)
Sections 6.2.2 and 6.2.3, especially the ABNF in Section 6:

- RFC5424 uses VERSION 1. Other integers use the registered-version
  space, but Parser Studio has **not** independently qualified a
  future VERSION 2/100 header contract. The v1 source observer must
  decline those unknown formats rather than reuse v1 field locations.
- RFC5424 TIME-SECFRAC is an optional decimal point followed by
  **1–6 digits**, not arbitrary precision.
- Section 6.2.3.1 explicitly calls the nanosecond timestamp with
  nine fractional digits invalid. Leap seconds, lowercase 't'/'z',
  impossible calendar dates and out-of-range timezone offsets are
  outside the qualified v1 source grammar.
- NILVALUE '-' is valid source text when the clock is not known.
  The original byte is preserved, but a missing timestamp need not
  be materialized into a trusted nonempty timestamp field.

## Provenance, isolation and source answer

A new isolated PoC branch is stacked ONLY on qualified RFC5424
source-ownership Draft PR #71 exact HEAD
07403224b8793a2098deae0794e9f7dff1583183.
Original cross-family PR #68 and its parent PRs, product HEAD
da94aa9, main, intentional Frontend 11/Backend 10 dirty changes,
Native Stellar/Fluentd, DP, sensors, production, credentials, release
and deployment are NOT modified.

Independent authored and source-derived **synthetic** frozen oracle
(before candidate scoring):
- Generator: scripts/poc/freezeStdRfc5424TimeAndVersion.py
- Fixture: scripts/poc/standardRfc5424TimeVersion.pinned.json
- SHA-256: 2a281fccd420261d1387569a1d73ef7a8984b9ab33fb2ff711f0bac6eba0eced
- Exactly fourteen narrowly scoped records: six valid supported v1,
  eight unsupported/invalid, including one RFC-published negative time
  example and unqualified non-v1 versions.
- Original full wire SHA/UTF-8 length, literal header/SD/message values,
  absolute byte intervals and source/native caveats fixed
  independently of the source observer.

No manufacturer-live wire or blinded field-value source truth is
created by these standards-derived inputs. No original commercial
customer data has been imported or redistributed.

## RED -> GREEN

- RED unchanged general envelope observer: four false-accepted source
  examples (fractional seconds of 7 and 9 digits and unqualified v2/100).
  Browser and independent byte-level RFC5424 v1 scanners already
  abstained on those sources. One initial test projection for NILVALUE
  erroneously assumed that a missing timestamp should appear as a
  nonempty field. The original independent frozen source oracle was
  **preserved**, and the test explicitly projects NILVALUE out of
  decoded field claims while still replaying that original source byte.
  The genuine four parser mismatches remained RED before the fix.
- GREEN minimal shared general source-observer change:
  TIME-SECFRAC strictly limited to six digits; only VERSION 1
  is interpreted under the v1 field-layout contract. Unknown future
  versions produce ABSTAIN rather than a false-success v1 field map.
  No vendor parser expression was added.
- All fourteen source version/timestamp cases, original UTF-8
  field positions, and independent source-byte/browser parity PASS;
  related focused suites 41/41 PASS.
- The source remains lexical REVIEW_ONLY where supported; true
  producing device clock, relay forwarding time, NTP correctness,
  timezone semantics beyond the RFC grammar and Native mapping
  remain NOT VERIFIED.

## Regression and exit gates

- SHA-pinned historical 1,361 original events, 2,892 mutated invalid
  samples (197 REVIEW_ONLY unchanged), and previously independent
  50 source examples remain historical safety replay, not a
  new accuracy denominator.
- The targeted replay after the fix shows zero changed source output,
  zero source byte drift and no newly promoted malformed cases.
- Full Vitest/English-only, TypeScript/Vite build and Exact-HEAD
  GitHub CI are independently mandatory and must be recorded only
  after their actual outcomes are observed.
- Real original manufacturer logs, forwarder relay provenance,
  timeQuality semantics, RFC5425 secured stream framing, Native
  Stellar/Fluentd and user E2E remain outside this PoC.

## Reproduction

    python3 scripts/poc/freezeStdRfc5424TimeAndVersion.py
    npx --no-install vitest run src/poc/standardRfc5424TimeVersionParity.test.ts
    npm test
    npm run build
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    git diff --check

Draft/unmerged, source stage only. No product/target deployment.
