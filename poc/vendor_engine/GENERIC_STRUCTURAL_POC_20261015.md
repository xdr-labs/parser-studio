# Generic Structural Parser PoC — 2026-10-15

## Decision question

Can Parser Studio reduce the endless growth of vendor-specific parsers by
extracting original security-log field/value spans from generic structure
instead of identifying a vendor first?

This PoC scores source extraction only. Field semantics, normalized destination
names, and whether a value represents source/destination/user/action are out of
scope.

Baseline commit: `dc73fc83854383de89656f10e3bbb477769a9747`.

## Candidate architecture

The candidate does not import Meraki, WatchGuard, Juniper, Cisco ISE, pfSense,
or ASA vendor-profile modules.

```text
raw event
  -> existing standards parsers (JSON / CEF / LEEF / Syslog / KV / CSV)
  -> vendor-agnostic structural segmentation
       - mixed positional + KV tokens
       - quoted/repeated KV
       - parenthesized positional groups
       - adaptive comma-KV with keys containing spaces
       - wide fully-consumed positional CSV
  -> deterministic admission from structural evidence
  -> optional learned structural recipe
  -> residual template candidate only
```

The standards parsers remain authoritative when they already parse the source
completely. The PoC does not replace the current Multi-Pass engine wholesale.

## Frozen-profile comparison

Ten public security-log shapes already qualified by the current parser were
frozen before the generic comparison. The generic candidate was then scored by
exact UTF-8 source span only; source-path names were intentionally ignored.

Results:

- 10 / 10 exact events.
- 186 TP / 0 FP / 0 FN source spans.
- Precision / Recall / F1: 1.000000 / 1.000000 / 1.000000.
- 7 malformed/lookalike controls: 0 false-complete.
- Existing complete standard formats remained on their existing standards
  parser path.

This comparison is a frozen current-parser structural oracle, not independent
manufacturer truth.

## New structures not completely handled by the frozen baseline

### Wide positional CSV

A public pfSense-style 29-column filterlog record was already extracted with
exact column spans by the existing CSV primitive, but remained PARTIAL because
column meanings were unknown.

The generic extraction-only rule promotes a fully consumed, Syslog-wrapped CSV
with at least eight positional columns without assigning column meanings.

- Baseline: PARTIAL.
- Candidate: SOURCE_PARSED.
- Source span sets: identical.
- Candidate residual bytes: 0.
- Short four-column comma prose control remains PARTIAL.

### Adaptive comma-KV

A public Cisco ISE-style authentication event contains comma-separated KV,
keys containing spaces, multi-word values, empty values, repeated keys, and
values that themselves contain '='.

- Baseline: PARTIAL, 16 source occurrences.
- Candidate: SOURCE_PARSED, 34 source occurrences.
- Independently declared expected KV tree: exact.
- Every candidate KV span decodes to the exact original source slice.
- Repeated `cisco-av-pair`: two ordered occurrences preserved.
- Candidate residual bytes: 0.
- A three-field lookalike is not promoted to SOURCE_PARSED.

## Fresh-holdout behavior

The first fresh six-event holdout exposed two conservative misses: a Meraki URL
shape with three KV fields plus URL/MAC evidence and a WatchGuard PID shape
with three KV fields plus multiple network positional values. The first pass
parsed 4 / 6 completely.

No vendor rule was added. Admission was changed once to accept a three-or-more
KV mixed record only when at least two independent network-structure values are
present (IP/host:port, MAC, URL, or endpoint tuple). The weak controls remained
incomplete.

After that change, a second fresh six-event holdout was frozen and no parser
changes were made:

- 4 / 4 events whose baseline oracle was SOURCE_PARSED remained exact.
- 2 / 2 Meraki custom records that the baseline left PARTIAL became
  SOURCE_PARSED with zero residual bytes.
- Their four additional positional spans per event are non-empty exact slices
  of the original source.
- No semantic role was assigned to those positional values.

## Structural recipe synthesis PoC

The synthesis layer learns structural mode only, never vendor identity.

Train -> holdout:

- Meraki mixed -> different Meraki mixed shape: exact.
- WatchGuard BSD/mixed -> different extended mixed shape: exact.
- Cisco ISE comma-KV -> changed-value holdout: exact.

Result: 3 / 3 holdouts passed.

This is deliberately smaller than a full PADS/FlashExtract-style program
synthesizer. It proves that a reusable structural recipe can be stored without
a vendor-specific parser, not that arbitrary grammars are already synthesized.

## Residual template PoC

A Cisco ASA deny message remains RAW_ONLY in the generic structural parser,
which is intentional because it is prose/position heavy.

Drain3 0.9.11 was trained on two value-mutated examples and evaluated on a
disjoint third example:

- template match: PASS;
- six expected variable spans;
- six candidate spans;
- exact span match: PASS;
- status remains SOURCE_SPAN_CANDIDATE_ONLY;
- semantic field names are not inferred;
- automatic apply remains disabled.

This supports using template mining only after deterministic structure parsing,
not as the primary parser.

## Regression gate

The final candidate was run in the same ignored fixture/dependency environment
used by the qualified source-engine work. Full `vendor_engine` discovery
completed **340 tests OK / 1 optional skip / 0 failures / 0 errors**. The skip
is the pre-existing optional Spell dependency check.

## Conclusion

The PoC supports an architectural change.

The current problem is not primarily insufficient vendor coverage. A large
part of the observed long-tail failures can be represented by a small number
of reusable structural primitives.

Recommended product direction:

1. Keep existing qualified JSON / CEF / LEEF / Syslog / KV / CSV parsers.
2. Add Generic Structural as another bounded Multi-Pass candidate.
3. Rank it by source accounting and structural evidence, never runtime or field
   count alone.
4. Reparse residual regions without destroying already accepted spans.
5. Cache learned structural recipes by source shape, not vendor name.
6. Keep Drain/template mining as a candidate-only residual stage.
7. Retain vendor profiles temporarily as regression/fallback evidence and
   retire them only when a broader independent corpus proves equivalence.

The PoC does not yet justify deleting vendor profiles or replacing the current
engine. It does justify stopping broad vendor-profile growth while a larger
generic-structure qualification corpus is built.

## Limits

- The frozen-oracle set is small and partially shaped by previously discovered
  failures.
- Field semantics and dictionary normalization were not scored.
- Recipe synthesis is mode-level, not full grammar/program synthesis.
- Residual template evidence is a small derived holdout, not open-world vendor
  qualification.
- No native Ruby/CONF, Stellar target, DP/sensor, UI, production, merge, or
  release validation is claimed.
