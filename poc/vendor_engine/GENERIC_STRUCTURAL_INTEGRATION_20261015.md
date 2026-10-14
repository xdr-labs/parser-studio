# Generic Structural Multi-Pass Integration — 2026-10-15

## Status

Generic Structural is integrated into the parser-core Multi-Pass path on the
integration candidate branch. This is **not** merged, released, deployed, or
validated against a Stellar DP/sensor target.

Integration base evidence head:
`8851784c6798dd09ba87989086455c93ad9e9389`.

PoC parser implementation remains byte-identical to the post-freeze evidence
candidate at `074b90e35de04c65fc7c5bec11d42a198d12130c`. Integration-specific
source identities and adjudication are attached outside the PoC parser.

## Integration policy

The execution order intentionally preserves existing compatibility:

1. Parse the qualified base source grammar.
2. Preserve verified public product profiles where they already qualify a
   complete event.
3. Preserve qualified CEF/LEEF standards behavior.
4. If the ordinary qualified result is still incomplete, evaluate Generic
   Structural.
5. Generic may replace the incomplete result only when:
   - Generic itself is SOURCE_PARSED;
   - no stable `source_segments` claim from the base is lost;
   - no non-empty, disjoint heuristic base claim is lost;
   - conflicting interpretations are resolved through the normal evidence
     adjudicator.
6. Existing complete results are never sent through Generic reinterpretation.
7. Existing vendor profiles remain long-tail fallback/regression evidence.

Generic Structural uses a dedicated `QUALIFIED_STRUCTURAL` evidence tier. It
is stronger than the incomplete qualified base but remains below declared
schema, qualified standards, and verified profiles.

## Source identity adapter

The PoC parser is intentionally unchanged. At the integration boundary, a
deep-copy adapter attaches exact tree identities for:

- `generic.prefix.N` -> `generic.prefix_tokens[N]`
- `generic.tokens.N` -> `generic.tokens[N]`
- `generic.groups.N` -> `generic.groups[N]`
- `generic.kv.KEY` -> the exact `generic.kv` or `generic.fields` key,
  with occurrence indexes for repeated keys.

This lets `candidate_from_event()` validate Generic output without altering
the frozen PoC implementation or its evidence.

## Juniper RFC5424 contract repair

The 708-event post-freeze corpus exposed seven
`CANDIDATE_DISPLAY_PATH_MISMATCH` exceptions on malformed Juniper SRX
structured-data records.

The repair keeps strict RFC5424 behavior fail-closed. The security-source
adapter may retain only the independently validated RFC5424 header when
structured-data later fails. All partial SD claims are rolled back before
candidate conversion.

Post-repair Juniper SRX holdout result:

- 105 events;
- 58 SOURCE_PARSED;
- 46 PARTIAL;
- 1 RAW_ONLY;
- 0 exceptions.

## Frozen integration gates

A value-free baseline ledger pins the pre-integration Multi-Pass state at
`8851784c6798dd09ba87989086455c93ad9e9389`.

### 948-event qualification corpus

Pre-integration baseline:

- 461 SOURCE_PARSED;
- 482 PARTIAL;
- 5 RAW_ONLY.

Integrated candidate:

- **684 SOURCE_PARSED**;
- 259 PARTIAL;
- 5 RAW_ONLY;
- **223 incomplete events promoted**;
- **461 / 461 prior complete events exact** by source-span digest;
- complete-event divergences: **0**;
- raw preserved: **948 / 948**.

### 708-event true post-freeze holdout

Pre-integration baseline:

- 283 SOURCE_PARSED;
- 384 PARTIAL;
- 34 RAW_ONLY;
- 7 exceptions.

Integrated candidate:

- **496 SOURCE_PARSED**;
- 182 PARTIAL;
- 30 RAW_ONLY;
- **213 incomplete events promoted**;
- **283 / 283 prior complete events exact**;
- complete-event divergences: **0**;
- all **7 / 7 prior exceptions repaired**;
- raw preserved: **708 / 708**.

Across the two non-overlapping corpora, all **744 / 744** previously complete
events retain exact source-span sets.

## Independent source gold

The integrated Multi-Pass path retains the independent references used by the
PoC:

- commercial structured formats:
  **391 scored events / 27,968 fields / 27,968 TP / 0 FP / 0 FN / F1 1.0**;
- JSON security formats:
  **94 events / 4,601 fields / 4,601 TP / 0 FP / 0 FN / F1 1.0**;
- combined:
  **485 events / 32,569 source fields / 0 FP / 0 FN**.

Field semantics and Dictionary normalization are not part of these source
accuracy scores.

## Regression

Final local `vendor_engine` discovery on the integration candidate:

- **357 tests OK**;
- **1 pre-existing optional skip**;
- **0 failures**;
- **0 errors**.

The integration qualification test independently replays both frozen corpora,
the value-free baseline ledger, the commercial reference, and the JSON
reference.

## Limits

- The 213 post-freeze promotions are structural coverage evidence, not 213
  independently gold-certified field/value events.
- F5 semicolon-delimited KV with unquoted multi-word values remains a known
  boundary-grouping weakness.
- Cisco ASA remains conservative and is not promoted by Generic Structural.
- Drain/template mining remains candidate-only.
- Existing product profiles are intentionally retained.
- No Ruby/CONF, native Fluentd, Stellar target, DP/sensor, release, merge, or
  production claim is made by this integration candidate.
