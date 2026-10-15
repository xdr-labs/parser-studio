# Generic Structural Massive-Scale PoC — 2026-10-15

## Scope

This PoC starts from integrated Multi-Pass HEAD `be48f13` and uses a frozen
Elastic public security-log corpus. Field semantics and destination dictionary
mapping are not scored. The goal is exact source field/value extraction and
raw/source-span preservation.

The exploratory massive corpus contains:

- 289 pinned upstream log files.
- 41 product-family labels.
- 3,607 unique logical events.
- 3,599 events not present in the previous 1,656-event qualification sets.

## Baseline

Before the massive-scale structural improvements:

- SOURCE_PARSED: 2,198 / 3,607 = 60.9%.
- PARTIAL: 669.
- RAW_ONLY: 740.
- Source spans: 96,920.
- Residual bytes: 1,659,831 / 4,764,659 = 34.8%.
- Raw preserved: 3,607 / 3,607.

## Massive-scale generic core result

After vendor-neutral structural primitives:

- SOURCE_PARSED: **2,465 / 3,607 = 68.3%**.
- PARTIAL: 603.
- RAW_ONLY: 539.
- Complete-event gain: **+267 events / +7.4 percentage points**.
- Source spans: **156,292**, up by 59,372.
- Residual bytes: **180,816**, down by 1,479,015 (about 89.1%).
- Raw preserved: **3,607 / 3,607**.

The reusable primitives that produced the gain are:

1. bounded JSON leaf budget 4,096 instead of 1,024;
2. bounded JSON depth 32 instead of 18;
3. RFC3164 multiple-space framing;
4. quote-aware comma KV;
5. bounded prefixed comma/semicolon KV;
6. wide PRI + ISO positional framing with structural/network evidence;
7. evidence-bounded short positional CSV;
8. semicolon colon-KV runs;
9. spaced quoted KV values;
10. quoted positional token punctuation handling.

The safety bounds remain explicit: 4,097 JSON leaves are rejected, excessive
depth remains rejected, weak delimiter lookalikes abstain, and short low-
evidence positional rows are not promoted.

## Existing qualification gates

The massive changes were re-run against prior frozen evidence:

- 948-event set: 684 SOURCE_PARSED; prior complete 461 / 461 exact.
- 708-event true post-freeze set: 498 SOURCE_PARSED; prior complete 283 / 283
  exact; 7 / 7 historical exceptions remain repaired.
- Independent commercial + JSON gold: **32,569 / 32,569 TP, 0 FP, 0 FN**.
- Full vendor_engine regression: **380 tests OK / 1 optional skip / 0 failures**.

## Candidate-only partial recovery

The remaining tail should not be forced to SOURCE_PARSED merely to improve a
completion metric. Three conservative additive layers were tested:

- validated IP/endpoint, MAC, URL and SHA-256 atoms;
- explicit delimiter label/value fields;
- strict standalone key=value islands.

Across all 3,607 events:

- events receiving at least one new source value: **769**;
- additional exact source spans: **1,319**;
- network values: 670;
- URLs: 37;
- SHA-256 values: 17;
- MAC values: 12;
- delimiter label values: 140;
- strict standalone KV values: 443;
- prior source spans preserved: **3,607 / 3,607**;
- raw preserved: **3,607 / 3,607**;
- SOURCE_PARSED count remains **2,465**; candidate-only recovery never promotes
  an incomplete event.

Residual bytes fall from 180,816 to 162,525, but residual reduction is not used
as proof of semantic parsing.

## Train-only template candidate

For repetitive prose/positional tails, template mining remains candidate-only.

A deterministic five-fold evaluation holds every incomplete event out once:

- holdout events considered: **1,113**;
- candidate events: **460 (41.3%)**;
- candidate source spans: **4,009**;
- source spans still new after atoms + labels + standalone KV: **3,329**;
- same-event SHA train/holdout overlap: **0**;
- semantic roles assigned: **false**;
- automatic apply allowed: **false**.

The useful candidate coverage is concentrated in repetitive FTD, Firebox and
secure-email shapes. High-diversity NetScreen messages do not benefit from the
current template routing.

## Diminishing-return boundary

After the generic core improvements, the largest remaining failures are mainly:

- long positional/prose firewall event-code messages;
- highly variable appliance message catalogs;
- product-specific sentence grammars with weak generic boundaries.

These are not good candidates for broader SOURCE_PARSED admission. Pushing
them into the generic core would trade recall for false-complete risk.

The preferred architecture is therefore:

1. qualified standards and verified profiles;
2. Generic Structural for strong reusable structure;
3. candidate-only lexical/label recovery for incomplete records;
4. train-only template source-span candidates for repetitive residual shapes;
5. AI/user-assisted rule synthesis for the remaining heterogeneous tail.

## Rejected experiment

A BSD tag-only envelope reinterpretation was tested and rejected. The existing
parser already captured the same visible header token values, so it changed
field interpretation without increasing source-value extraction.

## Decision

The massive PoC strengthens the earlier conclusion: Generic Structural should
remain a bounded Multi-Pass core candidate, but long-tail sentence formats
should not be solved by endless vendor rules or increasingly permissive
complete-event admission.

The next high-value product work is to integrate the proven massive-core
primitives, expose candidate-only partial recovery to the correction workflow,
and use train-only template/AI assistance only for unresolved residual regions.

No merge, release, production, DP/sensor or native-target claim is made here.
