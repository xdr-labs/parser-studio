# Generic Structural Parser — Post-Freeze Holdout (2026-10-15)

## Purpose

This holdout tests the already-frozen Generic Structural v2 candidate on
security logs collected only after parser head
`074b90e35de04c65fc7c5bec11d42a198d12130c` was fixed.

No parser tuning was performed before the measurements in this document.

## Corpus

The committed manifest
`GENERIC_STRUCTURAL_POSTFREEZE_HOLDOUT_20261015.json` pins:

- 708 globally unique physical-line events.
- 56 upstream fixture files.
- 5 product families.
- Cisco ISE: 275 events.
- F5 BIG-IP: 36 events.
- Juniper SRX: 105 events.
- Sophos UTM: 22 events.
- Sophos XG: 270 events.
- Upstream: `elastic/integrations` commit
  `49057c708569a51a9f87d2b45ef286812b093d2d`.
- Event overlap with the prior frozen 948-event corpus: **0**.

Raw fixtures remain only in ignored local research cache. The committed
manifest contains provenance, file hashes, counts, and an event-set digest.

## Frozen v2 result

Generic Structural v2, without post-holdout tuning:

- 496 / 708 SOURCE_PARSED = **70.1%**.
- 175 PARTIAL.
- 37 RAW_ONLY.
- 708 / 708 raw records preserved.
- Generic candidate exceptions: **0**.

The current Multi-Pass baseline on the same holdout:

- 283 / 708 SOURCE_PARSED = **40.0%**.
- 384 PARTIAL.
- 34 RAW_ONLY.
- **7 parser exceptions**.

All seven baseline exceptions are
`ValueError:CANDIDATE_DISPLAY_PATH_MISMATCH` on Juniper SRX RFC5424-like
records.

## Non-regression evidence

Among the 283 events the current baseline already classified SOURCE_PARSED:

- **283 / 283** have exact source-span equivalence under Generic Structural.
- Complete-event divergences: **0**.

Family breakdown of baseline-complete preservation:

- F5 BIG-IP: 32 / 32 exact.
- Juniper SRX: 53 / 53 exact.
- Sophos XG: 198 / 198 exact.

Cisco ISE and Sophos UTM had no SOURCE_PARSED baseline events in this holdout.

## New complete classifications

Generic Structural classifies 213 baseline-incomplete, non-exception events as
SOURCE_PARSED.

These promotions are **not independently certified as 213 exact events** in
this holdout. The baseline itself has known boundary errors on several of these
formats, so treating its partial spans as gold would be invalid.

Observed examples explain why raw span-subset comparison is insufficient:

- Cisco ISE baseline extraction can truncate a multi-word comma-KV value to
  its first word while Generic Structural preserves the full comma-bounded
  value.
- Sophos UTM baseline parsing can mistake commas inside quoted KV values for
  CSV separators, while Generic Structural recovers the actual quoted KV
  structure.
- F5 semicolon-delimited KV with unquoted multi-word values exposes a remaining
  Generic Structural boundary weakness; it should not be used as evidence for
  perfect field/value grouping.

Therefore the post-freeze holdout proves open-world structural coverage and
non-regression, but does not upgrade all 213 promotions to independently
verified field/value truth.

## New defect discovered in the current baseline

Seven Juniper SRX records crash the Multi-Pass candidate conversion.

The underlying source parser returns a RAW_ONLY RFC5424 event after malformed
structured-data quoting, but the partial RFC decoder has already accumulated
header/SD value spans without a matching field tree. `candidate_from_event`
then attempts to resolve those display paths and raises
`CANDIDATE_DISPLAY_PATH_MISMATCH`.

This is a fail-closed contract bug in the current baseline, not a Generic
Structural exception. It requires a separate repair before product integration.

## Product-family result

Frozen Generic v2 complete rates:

- Cisco ISE: 192 / 275.
- F5 BIG-IP: 34 / 36.
- Juniper SRX: 58 / 105.
- Sophos UTM: 13 / 22.
- Sophos XG: 199 / 270.

The lower Juniper result is deliberately conservative; all seven baseline-crash
records remain RAW_ONLY under Generic Structural rather than being guessed into
complete events.

## Decision

The post-freeze holdout strengthens the large-qualification conclusion:

1. Generic Structural generalizes beyond the 948-event tuning corpus.
2. Existing complete parsing is preserved exactly on all 283 qualified
   holdout events.
3. The candidate does not introduce parser crashes on the 708-event holdout.
4. The current baseline has a newly exposed Juniper candidate-contract crash.
5. Generic delimiter inference still needs work for semicolon-delimited KV with
   unquoted multi-word values.
6. The 213 newly complete records need syntax-specific or independent
   references before they are all called exact field/value parses.
7. Vendor fallbacks remain necessary while the long tail is qualified.

## Limits

- This holdout intentionally has no semantic-field scoring.
- The 213 promotions are not independent-gold events.
- Physical lines are treated as events because that is the upstream pipeline
  fixture representation.
- No Ruby/CONF, native Fluentd, Stellar target, DP/sensor, merge, release, or
  production validation is claimed.
