# Generic Structural Parser — Large Qualification PoC (2026-10-15)

## Purpose

The first Generic Structural PoC used a small public regression set. This
follow-up freezes a much larger security-product corpus before any v2 parser
changes and tests whether the architecture still generalizes.

Field semantics and normalization remain out of scope. The scored target is
original source field/value extraction, exact UTF-8 value spans, raw
preservation, and false-complete safety.

## Frozen corpus

The corpus was committed before v2 parser changes in
`GENERIC_STRUCTURAL_LARGE_QUALIFICATION_CORPUS_20261015.json`.

- 948 globally unique events.
- 10 security-product families.
- Cisco ASA: 261.
- SonicWall Firewall: 220.
- PAN-OS: 223.
- FortiGate: 118.
- Check Point: 23.
- CrowdStrike: 15.
- AWS WAF: 11.
- Zscaler ZIA: 9.
- SentinelOne: 8.
- Suricata: 60.

Raw upstream fixtures remain in ignored local research caches. The committed
manifest contains provenance, source digests, counts, and the digest of the
frozen event-SHA set.

## Large-corpus result

### Completeness and regression

Current qualified Multi-Pass baseline:

- 461 / 948 SOURCE_PARSED = 48.6%.

First Generic Structural PoC at parent `07cc6ef` on this newly frozen corpus:

- 567 / 948 SOURCE_PARSED = 59.8%.
- 8 previously complete events diverged.
- 114 incomplete events were promoted.

After v2 generic-only fixes discovered from the frozen corpus:

- 684 / 948 SOURCE_PARSED = 72.2%.
- +223 events over the current baseline.
- +23.5 percentage points absolute complete-event rate.
- 461 / 461 previously complete baseline events remain exact.
- 0 complete-event divergences.
- 948 / 948 raw records preserved.

The 223 new complete events are the PAN-OS positional CSV slice. Their values
were already source-extracted by the baseline but remained PARTIAL because the
column meanings were unlabeled. Because this PoC explicitly excludes semantic
field meaning, a wide, fully consumed positional CSV can be structurally
complete without assigning meanings to its columns.

Therefore this +223 result is a **structural-completeness improvement**, not a
claim that 223 events gained previously missing values.

## Independent gold

Two independent reference mechanisms were used.

### Commercial structured formats

Independent stdlib CSV/shlex/token-position reference:

- 391 scored events.
- 27,968 gold source fields.
- 27,968 TP / 0 FP / 0 FN.
- Precision / Recall / F1 = 1.0 / 1.0 / 1.0.
- 391 / 391 exact all-field events.

This includes the PAN-OS events promoted to structurally complete.

### JSON security formats

Independent Python stdlib JSON tree and token-span oracle:

- 94 events.
- AWS WAF, Suricata, SentinelOne, CrowdStrike.
- 4,601 gold source fields.
- 4,601 TP / 0 FP / 0 FN.
- 94 / 94 exact events.
- 0 false-complete events.

Combined independent-gold evidence:

- 485 events.
- 32,569 source fields.
- 32,569 TP / 0 FP / 0 FN.

## Generic fixes learned from the larger corpus

No vendor-name admission rule was added.

### Preserve fully accounted warnings

A Check Point record can have every source field extracted exactly while still
being PARTIAL because of RFC timestamp/duplicate-SD warnings. A residual-zero
warning record is no longer reinterpreted merely to obtain SOURCE_PARSED.

### Wide positional CSV

Fully consumed positional CSV is promoted only at a conservative width
threshold. This retains long PAN-OS/pfSense structures while rejecting a short
comma-separated ASA prose record.

### Rich KV with one explicit host/IP prefix

A single network-looking positional prefix followed by five or more KV
occurrences is accepted as mixed structure. This recovers SonicWall shapes
without importing a SonicWall profile.

All 220 qualified SonicWall baseline events are now exact under the generic
candidate.

### Ambiguous comma-KV abstention

If adaptive comma-KV rejects a record but the record contains multiple
comma-separated KV-looking fragments, the looser mixed scanner abstains. This
prevents certificate subject DNs such as nested OU/DC components from becoming
false top-level fields.

### Generic percent event-code tokens

The candidate now recognizes the structural form:

`%<token>-<number>-<number>:`

It does not recognize ASA or FTD by name and does not assign semantic meanings
to the three parts. Tokens are added only to incomplete events, never used by
themselves to claim SOURCE_PARSED, and are ignored when embedded inside an
already claimed value.

## Cisco ASA result

ASA remains the major long-tail weakness and is deliberately not called
complete.

Against the current parser's source-backed span set as a lower-bound reference:

Parent Generic PoC:

- 261 events.
- 1,049 baseline source-backed spans.
- 554 overlap / 495 missing.
- Lower-bound recall: 52.8%.
- 2 events were incorrectly promoted to complete on the large corpus.

Current Generic v2:

- 992 overlap / 57 missing.
- Lower-bound recall: 94.6%.
- 0 ASA events promoted to SOURCE_PARSED.
- 256 PARTIAL / 5 RAW_ONLY.

The additional generic event-code spans are exact source slices but are not
treated as semantic ASA fields.

## Template / recipe result

### Global Drain3

60/40 deterministic SHA split:

- 157 train / 104 holdout.
- 116 clusters.
- 20 holdout template matches.
- 8 SOURCE_SPAN_CANDIDATE_ONLY events.

Coverage is too low for primary parsing.

### Event-code-routed train-only recipe

Routing by the generic numeric event-code shape, with no vendor-name route:

- 29 train-qualified recipe models.
- 45 / 104 holdout events routable.
- 8 actual template matches.
- 5 source-span candidate events.
- On the holdout lower-bound comparison, Generic alone missed 28 baseline
  spans; the recipe reduced this to 24.

Only four additional lower-bound spans were recovered. This is too small to
justify integration complexity.

Drain/template output therefore remains candidate-only and automatic apply
remains disabled.

## Regression gate

The final v2 candidate was run in the same ignored fixture/dependency
environment used by the qualified source-engine work.

- Full `vendor_engine` discovery: **345 tests OK**.
- Failures: **0**.
- Errors: **0**.
- Skips: **1**, the pre-existing optional Spell dependency check.
- Dedicated Generic Structural small + large qualification tests: **13 / 13
  PASS**.

## Decision

The expanded PoC strengthens the original architecture decision:

1. Keep qualified JSON / CEF / LEEF / Syslog / KV / CSV primitives.
2. Add Generic Structural as a bounded Multi-Pass candidate.
3. Use source accounting and structural evidence for admission.
4. Treat wide positional structure as valid extraction without inventing field
   semantics.
5. Add generic structural envelopes such as percent event codes when they
   improve exact source extraction without completeness inflation.
6. Keep existing vendor profiles as fallback/regression evidence for the
   remaining long tail, especially ASA.
7. Do not make Drain3 or learned templates the primary parser.
8. Do not retire vendor fallbacks until a larger independent corpus proves the
   remaining source-backed spans are preserved.

## Limits

- Upstream integration fixtures are not customer-production traffic.
- Baseline span comparison for ASA is a lower-bound reference, not independent
  manufacturer truth.
- Independent gold directly covers 485 of the 948 events.
- Field meaning, target dictionary mapping, Ruby/CONF generation, native
  Fluentd execution, DP/sensor application, and product release are not
  claimed by this PoC.
