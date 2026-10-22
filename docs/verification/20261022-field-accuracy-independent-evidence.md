# ACC-2 — independent source-field evaluation (2026-10-22)

## Scope and immutable baseline

- Research branch: `research/field-accuracy-mdl-shadow-20261022` / Draft PR #142, isolated from the product and PR #140/#141.
- Product baseline: existing RFC/CEF/LEEF/JSON/Generic Multi-Pass and Funnel source, with the product's **actual schema/framing fail-closed status gate**. Shadow ranking is read-only and cannot alter public Preview or generated parsers.
- The original MDL proxy weights remain those authored before opening the pinned independent holdouts. Oracle SHA pins and the original source checks are enforced before scoring; no customer raw source or field value is committed.
- This evidence tests **field path, original UTF-8 lexeme span and decoded value** only where complete truth exists; it is **not** a Stellar Cyber 7.0 source/destination semantic role or native parser benchmark.

## Pinned source-only evaluations

| Frozen oracle source | Verified scope | Product | Shadow | Interpretation |
| --- | --- | --- | --- | --- |
| Hand-authored synthetic set | 6 COMPLETE / 26 claims plus 1 UNSCORABLE | 26/26 claims | 26/26 | Test-harness functional smoke, **not independent** |
| Publisher-authored W3C standard example | 4 events / 12 published name + decoded value + original span assertions | 12/12 | 12/12 | Independent publisher reference; original transport/compiler schema remains **PARTIAL** for all 4 |
| Frozen independent JSON byte oracle | 588 complete JSON events / **15,655 exact fields**; 177 unsupported/non-JSON unscorable records excluded | 15,655 TP, 0 FP, 0 FN; per-oracle F1 1.0 | Identical | 40 development / **548 sealed holdout**; independent JSON lexical/typed correctness, **not** manufacturer roles |
| Independent CEF/Syslog publisher assertions | 16 of 30 originals / **145 independently asserted lexical source spans**; remaining 9 duplicates, 3 unscorable, 2 invalid controls excluded | 123/145 exact (CEF 110/114; Syslog 13/31) | Identical | **Partial source truth** only: no Precision/F1, native compatibility, or inferred semantic role score |

## Candidate-pool and scoring result

1. The JSON corpus produced exactly **one** eligible candidate per scored event (588 total); both product and shadow retained that candidate. There is no possible MDL winner change for these samples. The observed p50/p99 times in the pinned digest report are **local single-process microbenchmarks**, not a production performance claim or a fair head-to-head new-algorithm benchmark.
2. The W3C reference produced **12 candidate snapshots** across four source records. **8 unqualified candidate snapshots were rejected by the preserved source/schema guard**. Original Preview and Shadow both retained PARTIAL on every record and matched the 12 independently published claims. This exposed why a bare Funnel SOURCE_PARSED result must never bypass the schema gate.
3. For the upstream non-JSON assertion set, 16 original records each yielded one retained candidate. The **22 unmatched publisher claims** are split into 4 CEF and 18 Syslog observations. Further digest-only inspection found four CEF `cfp1` original-value boundaries differing by one whitespace byte from publisher assertions, while three Syslog claims cover larger/different message or timestamp spans; the rest do not match an individual extracted span. Do **not** remove CEF whitespace generically: current grammar intentionally preserves ambiguous original value whitespace, and a boundary disagreement with one publisher fixture does not authorize changing the shared grammar. Existing `SOURCE_PARSED` status on six samples coexists with some mismatched published lexical assertions; this is **review evidence**, not a manufacturer-wide proved false-complete rate.
4. Neither set demonstrated **any** improved independently asserted field extraction after shadow scoring. The independent corpus has insufficient distinct scored manufacturer clusters for confidence intervals or a general manufacturer F1 claim. The evidence therefore does **not** pass the gate for product MDL scoring integration.

## Reproduction and evidence files

- Self-authored smoke: `docs/verification/20261022-field-accuracy-shadow-synthetic-score.json`
- Published W3C golden: `docs/verification/20261022-field-accuracy-publisher-w3c-score.json`
- Frozen JSON (development + sealed): `docs/verification/20261022-field-accuracy-generalization-blind-score.json`
- Independent partial CEF/Syslog assertions: `docs/verification/20261022-field-accuracy-nonjson-publisher-score.json`
- Local golden sources remain in approved protected `/home/aella/.local/state/` directories and are never copied to this repository. All four reports emit counts/hashes/metadata, not source text, original values, model prompts or customer credentials.
- Run CI-safe tests with `python3 -m unittest discover -s tests -p 'test_field_accuracy_shadow_20261022.py' -v`. Publisher and frozen-oracle CLI tools require explicit private source/oracle/summary paths and fail closed on SHA or scope mismatches; they are intentionally not executed in public CI.

## Decision and next action

**ACC-0** and preliminary **ACC-1** are implemented for research. **ACC-2** now has independent goldens and a documented result, but a meaningful multiple-candidate **unknown/partial** holdout has **not** been demonstrated. Keep the candidate as Draft, freeze the weights, and continue investigating qualified additional partial-grammar oracles rather than changing the parser. ACC-3 low-shot residual learning and ACC-4 7.0 role-abstention may be evaluated off-product once independently scored representative cases exist.

Do not merge an unproven MDL evaluator into runtime or regenerate a completed product gate merely for the research lane. PR #140/#141 user-journey acceptance remains separate, and any privileged deployment/production/DP/sensor/native-target operations remain outside scope.
