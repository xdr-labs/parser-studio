# Funnel / Beam Accuracy-First Auto Parser PoC — 2026-10-15

## Decision

**POC_SUCCESS_LIMITED**

A bounded multi-pass Funnel orchestrator is a viable next Auto Parser layer above the current Multi-Pass / Generic Structural engine. The PoC demonstrates that later passes can recover additional independently validated source spans after an earlier pass exposes more structure, while preserving every accepted baseline claim.

The PoC does **not** justify replacing the current parser engine, and it does not yet prove that keeping multiple live beam branches improves accuracy over a single best branch. The beam abstraction remains useful for future ambiguity, but current productization should prioritize multi-pass replay and evidence-aware admission.

Product baseline: 4596f4629a4cb7b900eb459cadffb0d2813c7957.

This branch is research-only. No product merge, release, production, target loader, credentials, DP/sensor, Ruby/CONF, or native target action is performed here.

## Objective

Source extraction accuracy is the primary objective; runtime is not an acceptance metric. Multiple parser attempts and repeated passes are acceptable provided execution is bounded and every accepted result preserves the original source exactly.

The PoC evaluates:

1. fan-out across existing parser families instead of committing to one format too early;
2. residual-only re-parsing without replacing accepted spans;
3. cross-event structural learning over a training batch;
4. replay so later passes can build on earlier exact additions;
5. bounded beam survival for ambiguous alternatives;
6. deterministic stop when no better state is found.

## Architecture

The prototype uses:

1. **Qualified baseline** — current parse_security_multipass(); existing SOURCE_PARSED results are immutable.
2. **Whole-record fan-out** — source parser, CEF, LEEF, Generic Structural, and already-qualified product parsers.
3. **Residual fan-out** — only residual byte ranges are eligible; accepted source spans cannot be replaced.
4. **Cross-event learners** — delimited anchors, event templates, relative R-gram, leading numeric skeleton, CSV child labels, extended BSD envelope, and repeated typed residual labels.
5. **Replay** — hypotheses are learned only from the training partition and replayed over that partition before evaluation.
6. **Beam survival** — up to four structurally distinct states may survive in the research configuration.
7. **Bounded stop** — maximum six passes and immediate stop when no new beam state survives.

Evaluation data never retrains the evaluated hypothesis bundle.

## Admission policy

### Existing complete result

An existing SOURCE_PARSED result is never reinterpreted by Funnel.

### Partial recovery

Partial recovery may add exact source spans, but it keeps the parent's issues and residual regions and cannot certify whole-record completeness.

### Learned complete candidate

A learned candidate may promote to SOURCE_PARSED only when it preserves every baseline source claim, adds values only from previously residual source bytes, preserves raw source, passes truncation/deletion/NUL adversarial mutations, and fails closed when a required learned structural anchor is removed.

When source spans are useful but completeness proof fails, Funnel may retain those spans while deliberately keeping the event PARTIAL.

### Bare residual Generic Structural

Direct admission of Generic Structural over an arbitrary residual is disabled.

A security control exposed a residual where locally complete Generic segmentation added 16 spans, but only 10 matched official expected values and six remained unvalidated. Exact byte accounting alone therefore does not prove field boundaries.

Decision: REJECT_DIRECT_RESIDUAL_GENERIC_ADMISSION.

Generic Structural remains available as the already-qualified whole-record candidate and as evidence used by stronger cross-event hypotheses.

## Strict independent-reference gain

The current Funnel preserves the exact byte ranges independently validated in the closed Structural Hypothesis PoC:

| Family | Funnel added spans | Match prior independently validated ranges |
| --- | ---: | ---: |
| Cisco Secure Email | 44 | 44 |
| Snort IDS/IPS | 60 | 60 |
| Sophos UTM | 54 | 54 |
| **Total** | **158** | **158** |

Extra unvalidated ranges: **0**.

Cisco Secure Email has 21 augmented split occurrences: five pass the stronger complete-promotion gate and 16 retain the exact recovered spans as PARTIAL. Snort and Sophos remain partial-only.

Machine evidence: funnel-beam-reference-validation-summary.json.

## Real multi-layer stacking

A dedicated WatchGuard development-only replay proves that later passes actually add source fields after an earlier structural layer:

- training events: **118**
- holdout events: **63**
- events that traverse extended-BSD -> typed-label: **6**
- added spans on those chained events: **48**
- independently validated: **48 / 48**
  - official envelope exact spans: 42
  - official expected-value exact spans: 6
- unvalidated spans: **0**
- maximum event depth observed: **3 passes**

This is development evidence, not prospective open-world generalization evidence.

Machine evidence: funnel-beam-multilayer-watchguard-summary.json.

## Ablation: pass depth vs beam width

The same security positive/development matrix was evaluated under four configurations.

| Configuration | Added span occurrences | Improved events | Max observed pass |
| --- | ---: | ---: | ---: |
| 1 pass, beam 1 | 5,794 | 855 | 1 |
| 1 pass, beam 4 | 5,794 | 855 | 1 |
| up to 6 passes, beam 1 | 5,844 | 855 | 3 |
| up to 6 passes, beam 4 | 5,844 | 855 | 3 |

Observed deltas:

- **multi-pass gain over one pass: +50 source-span occurrences**
- beam 4 gain over beam 1 at one pass: **0**
- beam 4 gain over beam 1 with multi-pass: **0**

The +50 comes from a later typed-label layer that becomes admissible after an earlier structural pass. Therefore **repeated passes have demonstrated extraction value**.

No accuracy benefit from beam width greater than one is demonstrated by the current corpus. Keep the beam abstraction for future competing hypotheses, but do not claim beam branching itself improves accuracy yet.

Machine evidence: funnel-beam-ablation-summary.json.

## Fresh holdout behavior

Previously frozen security-only holdouts were re-evaluated with the exact Funnel implementation:

- holdout #2: **49 / 49 baseline-incomplete events abstained**
- holdout #3: **1 / 1 baseline-incomplete event abstained**
- complete-result divergence: **0**
- baseline span loss: **0**
- raw mismatch: **0**

Additional passes do not create fields merely because computation is available.

Machine evidence: funnel-beam-fresh-holdouts-summary.json.

## Broad stress run

Three deterministic splits over the security-log stress matrix:

- train occurrences: **6,723**
- eval occurrences: **3,621**
- small controls: **309**
- existing complete exact-preserved: **2,167 / 2,167**
- improved eval occurrences: **855**
- added source-span occurrences: **5,844**
- partial improvements: **847**
- complete promotions: **8**
- mutation attempts against complete promotions: **32**
- mutation false-complete: **0**
- raw mismatch: **0**
- baseline span loss: **0**
- prior-complete divergence: **0**
- maximum pass depth observed: **3**

Improvement provenance:

- learned R-gram complete: 8
- learned R-gram retained as partial: 13
- CSV child-label partial: 12
- extended-BSD partial: 798
- numeric-prefix partial: 24
- typed-label partial: 50

The 5,844 value is repeated split/development occurrence evidence. It is **not** 5,844 independent open-world gold fields.

Machine evidence: funnel-beam-security-poc-summary.json.

## Safety invariants

- raw source identity unchanged;
- baseline source claims never removed;
- prior complete events extraction-identical;
- partial-only layers cannot certify completeness;
- complete learned promotion requires adversarial mutation safety;
- bare residual Generic atomization rejected;
- pass count bounded to six;
- beam width bounded to four;
- evaluation never retrains its evaluated hypothesis bundle;
- runtime is not ranked.

## Regression and reproducibility

Current research implementation:

- Funnel core SHA-256: 85d90ba07f13544fb337007699ca3b143315bd8434df3a0a4a490b4e3e9098ff
- Structural learner SHA-256: 1acd829d41176a696afc2ce7561f5c6af397c75eb15e22d67b6073008d501ec5
- Structural learner is byte-identical to research commit 57be1b9872b5dc9ba516b58fa7c1c976bbebd0d4.

Regression:

- focused Funnel + Structural suite: **38 / 38 PASS**
- full vendor_engine discovery: **444 tests PASS / 14 optional skips / 0 failures / 0 errors**
- optional Drain3 tests executed with the existing ignored .cache/drain_deps path on PYTHONPATH.

verify_funnel_beam_evidence.py checks implementation hashes, independent-reference ranges, frozen-holdout abstention, broad no-loss gates, real multi-layer evidence, and regression summaries.

## Product direction

If productized, retain the current engine and add Funnel orchestration:

current Multi-Pass -> candidate fan-out -> residual candidates -> batch learning -> replay -> deterministic no-loss adjudication

Do not replace the current engine with a monolithic learner.

For the first product integration:

1. make **multi-pass replay** the primary new behavior;
2. retain the beam abstraction internally;
3. default to a single surviving branch unless a newly frozen security holdout proves an exact-span benefit from beam_width > 1;
4. preserve candidate fan-out so alternate parsers can still be evaluated and audited even when only one branch survives;
5. keep the user-facing Auto Parser flow as one automatic action.

Productization gates remain:

1. independently scored added-span precision 100% for admitted positive gains;
2. raw preservation 100%;
3. baseline span loss 0;
4. prior complete divergence 0;
5. mutation false-complete 0;
6. every newly introduced automatic grammar family proves gain on a newly frozen security-only holdout before complete admission.
