# Generic Structural Landing on Current Source Engine — 2026-10-15

## Purpose

This landing candidate reapplies the completed Generic Structural PoC and
Multi-Pass integration work on top of the current Source Engine Draft PR #16
head, rather than leaving the integration stacked only on the older PoC branch.

Current Source Engine baseline:

`193a4ec74ca1189208814dab410ea5c83f69ced6`

This baseline already includes the later beginner-UX engine work, batch preview,
and the newer Cisco ASA/FTD full-message merge behavior.

## Composition

The landing branch preserves both lines of work:

- current PR #16 batch preview / recovery / ASA changes;
- security-source generalization profiles and LEEF compatibility;
- frozen Generic Structural PoC evidence;
- malformed RFC5424 candidate-contract repair;
- `QUALIFIED_STRUCTURAL` evidence tier;
- Generic Structural long-tail Multi-Pass integration;
- existing profile and CEF/LEEF priority.

The frozen Generic PoC parser remains byte-identical to its evidence candidate.
Landing-specific source identity and adjudication stay outside that parser.

## Latest-baseline qualification

A value-free landing ledger captures the current PR #16 pre-integration state
at `193a4ec`.

### 948-event qualification corpus

Current PR #16 baseline:

- 465 SOURCE_PARSED;
- 478 PARTIAL;
- 5 RAW_ONLY.

Landing candidate:

- **688 SOURCE_PARSED**;
- 255 PARTIAL;
- 5 RAW_ONLY;
- **+223 incomplete events promoted**;
- **465 / 465 prior complete events exact** by source-span digest;
- complete divergence: **0**;
- raw preserved: **948 / 948**.

The four extra complete events relative to the older 461-event baseline are the
newer ASA/FTD improvements already present in current PR #16. They remain
preserved.

### 708-event true post-freeze holdout

Current PR #16 baseline:

- 283 SOURCE_PARSED;
- 384 PARTIAL;
- 34 RAW_ONLY;
- 7 exceptions.

Landing candidate:

- **496 SOURCE_PARSED**;
- 182 PARTIAL;
- 30 RAW_ONLY;
- **+213 incomplete events promoted**;
- **283 / 283 prior complete events exact**;
- complete divergence: **0**;
- all **7 / 7 prior exceptions repaired**;
- raw preserved: **708 / 708**.

Across both frozen corpora, the current PR #16 baseline contributes **748**
already-complete events and the landing candidate preserves **748 / 748**
exact source-span sets.

## Independent source gold

The landing Multi-Pass path retains:

- commercial structured formats:
  **391 scored events / 27,968 fields / 27,968 TP / 0 FP / 0 FN / F1 1.0**;
- JSON security formats:
  **94 events / 4,601 fields / 4,601 TP / 0 FP / 0 FN / F1 1.0**;
- combined:
  **485 events / 32,569 source fields / 0 FP / 0 FN**.

Field semantics and Dictionary normalization are not included in these source
accuracy scores.

## Regression

Final local `vendor_engine` discovery on the landing candidate:

- **364 tests OK**;
- **1 pre-existing optional skip**;
- **0 failures**;
- **0 errors**.

The landing qualification separately replays the two frozen corpora against the
value-free `193a4ec` baseline ledger and independent commercial/JSON
references.

Historical PoC/PR #20 tests validate their immutable committed summaries;
current landing behavior is validated by the separate landing qualification
gate. This avoids treating legitimate later ASA improvements as historical
evidence drift.

## Limits

- The post-freeze promotions are structural coverage evidence, not all
  independently gold-certified field/value events.
- F5 semicolon-delimited KV with unquoted multi-word values remains a known
  boundary-grouping weakness.
- Cisco ASA remains conservative outside qualified known-message paths.
- Drain/template mining remains candidate-only.
- Existing vendor profiles remain retained.
- No merge, release, production, DP/sensor, auth, Ruby/CONF, or native-target
  action is claimed by this landing candidate.
