# Generic Structural Parser — Post-Freeze Holdout (2026-10-15)

## Why this holdout exists

The 948-event large corpus was used to develop the v2 Generic Structural
candidate, so it is not sufficient as final unseen evidence. The parser was
therefore frozen at `074b90e35de04c65fc7c5bec11d42a198d12130c` before a
second corpus was selected or downloaded.

No parser code was changed after this holdout was selected.

## Frozen source

Upstream: `elastic/integrations` at commit
`49057c708569a51a9f87d2b45ef286812b093d2d`.

Selection was mechanical: every `.log` file from five pipeline-test
directories, then every globally unique nonblank physical line.

- 56 upstream files.
- 708 unique events.
- 5 product families.
- Cisco ISE: 275.
- Sophos XG: 270.
- Sophos UTM: 22.
- F5 BIG-IP: 36.
- Juniper SRX: 105.
- Event overlap with the earlier 948-event corpus: **0**.

Raw logs remain in ignored local cache. Only provenance, hashes and aggregate
results are committed.

## Result

Across all 708 events:

- Existing qualified Multi-Pass: 283 SOURCE_PARSED.
- Frozen Generic Structural: **496 SOURCE_PARSED**.
- Absolute gain: **213 events**.
- Complete-event rate: 40.0% -> **70.1%**, about **+30.1 percentage points**.
- Raw preserved: **708 / 708**.
- Generic exceptions: **0**.

Most importantly, all 283 events that the existing engine already considered
complete remained exact by source-span set:

- 283 / 283 exact.
- 0 complete-event divergences.

Family-level new structural completions:

- Cisco ISE: +192.
- Sophos UTM: +13.
- Juniper SRX: +5.
- F5 BIG-IP: +2.
- Sophos XG: +1.

## Interpreting baseline-span differences

A naïve comparison says promoted Generic events omit 557 spans emitted by the
existing incomplete parser. Those spans were audited before drawing a
conclusion.

- **0 / 557** had a stable `source_segments` identity.
- **551 / 557** non-empty spans overlap Generic source-value spans and are
  therefore boundary/re-segmentation differences, not disjoint value loss.
- The remaining **6 / 557** were zero-length empty heuristic spans.
- Non-empty, disjoint baseline spans lost by Generic: **0**.

Representative failure modes in the old incomplete parser included:

- taking only the first word of a multi-word Cisco ISE value;
- consuming a long semicolon-delimited F5 record as one `action` value;
- splitting Sophos UTM quoted text into very large false CSV columns.

The six zero-length ISE spans came from an empty-value interpretation of a
field whose Generic parse continues into a visible non-empty source value.

This does **not** make the 213 promotions independent gold. It shows that the
apparent baseline-span losses are weak heuristic claims rather than identified
source fields.

## New baseline defect found by the expanded corpus

Seven Juniper SRX records cause the current qualified Multi-Pass baseline to
raise `CANDIDATE_DISPLAY_PATH_MISMATCH`.

The underlying RFC5424 source decoder encounters malformed structured-data
quoting after it has already accumulated exact header/SD value spans, but the
failed record has no matching field tree. `candidate_from_event` then attempts
to resolve those orphan display paths and raises the exception. This is a
source-event/candidate-contract consistency defect, not a Generic Structural
failure.

The frozen Generic candidate raises no exception on any of the 708 records.
For those seven records it remains conservative rather than claiming
completeness.

This is a separate baseline/adjudicator defect discovered by the larger
corpus; it is not counted as Generic accuracy improvement.

## Combined PoC evidence

Development/qualification corpus:

- 948 events / 10 product families.
- 461 -> 684 structurally complete.
- 461 / 461 existing complete events preserved exactly.
- Independent gold: 485 events / 32,569 source fields / 0 FP / 0 FN.

Post-freeze holdout:

- 708 events / 5 additional product families.
- 283 -> 496 structurally complete.
- 283 / 283 existing complete events preserved exactly.
- 0 Generic exceptions.

Descriptively, the two non-overlapping corpora contain **1,656 events across
15 product-family labels**. The post-freeze set is the stronger evidence
because the parser was frozen before its selection.

## Decision

The post-freeze holdout strengthens the architecture decision:

1. Generic Structural should be integrated as a bounded Multi-Pass candidate,
   not as a wholesale replacement.
2. Existing complete results must remain protected from reinterpretation.
3. PARTIAL results may be structurally re-segmented when evidence is stronger;
   weak heuristic composite spans must not automatically veto better
   structure.
4. Field semantics remain downstream. A positional field can be valid source
   extraction without knowing its security meaning.
5. Cisco ASA and residual prose remain conservative; Drain/template mining is
   not promoted to the primary parser.
6. The newly exposed Juniper `CANDIDATE_DISPLAY_PATH_MISMATCH` should be
   fixed independently in the existing Multi-Pass contract/adjudicator.

## Limits

- The 213 post-freeze promotions do not all have independent field-level gold.
- F5 semicolon-delimited KV with unquoted multi-word values still exposes a
  boundary-grouping weakness; its promoted records must not be described as
  independently exact field/value parses.
- Upstream integration fixtures are test data, not customer-production logs.
- Field semantics, Dictionary mapping, Ruby/CONF, native Fluentd, DP/sensor and
  release validation remain out of scope.
