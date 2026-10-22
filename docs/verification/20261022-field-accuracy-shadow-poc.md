# Field-accuracy and MDL-proxy candidate shadow — initial PoC (2026-10-22)

## Scope and decisions

This is an **isolated experimental ACC-0 / ACC-1 research candidate** based on
`origin/main=7387b716a9f4febb15cc08866fa0014da6f72453`.
It is not incorporated in public `app.parser.xdr.ooo`, the normal Multi-Pass
call path, active UI PR #140/#141, Fluentd/native compiler, or any DP/sensor.
No automatic LLM processing or new manufacturer-specific parser was added.

The source already has qualified candidate conflict arbitration in
`runtime/multipass/multipass_adjudicator.py` and additive residual learning
in `runtime/multipass/bounded_funnel.py`. A second runtime evaluator would
duplicate accepted behavior and risk changing existing `SOURCE_PARSED` events.
Instead, this experiment imports immutable candidate snapshots and computes a
*side-by-side* MDL-inspired rank without changing the product-selected event.

## Implemented

- `docs/06_ROADMAP_AND_ACCEPTANCE.md`: ACC-0 through ACC-5 ordered research
  lane, independent-golden and holdout gates, no semantic overclaims.
- `runtime/multipass/accuracy_shadow.py`: bounded source SHA/size and UTF-8
  boundary checks; original span coverage; baseline field-claim preservation;
  incompatible overlap rejection with valid nested parent/child containment;
  JSON lexical-vs-decoded comparison; non-JSON unresolved decoding reported
  rather than falsely failed or certified; new unverified decoded fields
  ineligible for automatic promotion.
- The MDL-*proxy* score combines residual bit cost, field source boundary/name
  description cost, weak evidence and issue penalties. These weights are
  **unvalidated research hypotheses**, not learned MDL optimum or confidence
  probability. Candidate snapshots and pools are fixed before shadow ranking.
- `scripts/verification/field_accuracy_shadow_poc.py`: UTF-8 lexeme-pinned
  field name/value/occurrence/span goldens, per-family micro field counts,
  false-complete detection, private source non-disclosure and strict
  `UNSCORABLE` exclusion; avoids vacuous perfect F1 for empty-family
  ground truth.
- `tests/test_field_accuracy_shadow_20261022.py`: positive and malicious
  source-byte, value, decoding, nested span and unknown-golden tests.
- `.github/workflows/quality.yml`: fast deterministic guard for this
  additional research code; normal CI and browser suites are untouched.

## Frozen initial evidence

- Fixture: `tests/fixtures/field-accuracy-synthetic-v1.json`
- Source class: **SELF_AUTHORED_SYNTHETIC_NOT_INDEPENDENT_VENDOR_GROUND_TRUTH**.
- SHA-256 of fixture: `b82668d0d269eee9349f8f210ee1bebcea27023eec7287b0e0f6639ea385294b`.
- Output: `docs/verification/20261022-field-accuracy-shadow-synthetic-score.json`
- Initial completed synthetic fields: 26 exact claims in six fully annotated
  records (KV, quoted KV, JSON Unicode escape, CEF, RFC5424 UTF-8 text and
  empty unknown). One malformed record stays `UNSCORABLE`.
- Observed product single-event baseline, first-ranked fixed-pool candidate,
  and MDL-proxy shadow: each 26 exact / 0 missed / 0 false in this **tiny,
  deliberately easy synthetic test**, with 0 false-complete.
- **There were only seven total candidate snapshots across seven cases and
  zero shadow selection changes.** This means the fixture verifies wiring,
  accounting and noninterference, **NOT that MDL is more accurate**. The
  adversarial unit fixture confirms that a spurious field with no extra
  source coverage is penalized, but it is not a vendor-golden A/B improvement.
- Source-values not printed by the scoreboard; private fixture case IDs appear
  only as truncated SHA-256 digests in aggregate review metadata.
- No performance p99, calibration, vendor generalization, semantic field
  accuracy or producer-wire evidence claimed; these are unverified.

## Gates before any product integration

1. Supply or identify **independently established** exact name/decoded
   value/original lexeme/UTF-8 span oracles from existing protected reference
   corpora. Preserve provenance and SHA; do not derive truth by accepting
   Parser Studio output. Clearly distinguish full from incomplete/oracle-free
   records.
2. Evaluate a real **competing-candidate pool** with the same frozen
   candidate snapshots for original and shadow ranking. Maintain separate
   product-equivalent baseline (default beam width 1) and research beam=4
   measurements, and freeze train/holdout by manufacturer and template.
3. Report per-family precision/recall/F1, mistaken `SOURCE_PARSED`,
   recovered-only precision, wrong-role/abstention where independently labeled,
   and source/no-loss regressions. Bootstrap only with enough independent
   clusters; measure latency on representative volume.
4. Promote **only** if independent holdout evidence supports meaningful
   accuracy improvement without accepted-source regression. Otherwise keep
   the current engine. Do not merge the research PR merely to increase
   structural coverage.

## Reproduce (read-only)

```bash
python3 -m unittest discover -s tests -p 'test_field_accuracy_shadow_20261022.py' -v
python3 scripts/verification/field_accuracy_shadow_poc.py
```

Product feature acceptance, draft compiler compatibility, release/merge,
development rollout, proprietary Stellar target import and sensor operations
are separate decisions. This research is not a release blocker.
