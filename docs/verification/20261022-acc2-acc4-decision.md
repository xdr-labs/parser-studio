# Parser Studio ACC-2–ACC-4 — bounded field-accuracy research decision (2026-10-22)

## Decision

**Keep the existing Standard Grammar-first / Multi-Pass / Generic Structural
runtime unchanged. Do not integrate the uncalibrated MDL-proxy selector.**
The reviewed independent oracles provide valuable field extraction evidence,
but all observed candidate pools in these datasets have one eligible
candidate. There is no measured improvement from reranking and thus no
experimental basis to justify a runtime scoring replacement, runtime LLM,
or a new Grammar Induction subsystem.

This report is not a production release or native Stellar target acceptance.

## ACC-2: independent field-level evidence (pinned private local sources)

| Oracle/scope | Scorable events | Independently asserted fields | Product exact | Shadow exact | Interpretation |
| --- | ---: | ---: | ---: | ---: | --- |
| Frozen development JSON, independently decoded/tokenized | 40 | 1,302 | 1,302 | 1,302 | Exact name, typed value and original UTF-8 byte spans; previously qualified data |
| Sealed JSON holdout (one Suricata-related family) | 548 | 14,353 | 14,353 | 14,353 | Exact name, typed value and byte spans; **not** vendor-wide semantic or role validation |
| Publisher W3C reference | 4 | 12 | 12 | 12 | Exact published field/source claims; the four records remain SOURCE_PARTIAL by source framing; **not** complete vendor field precision |
| Non-JSON CEF and Syslog publishers | 16 of 30 originals | 145 asserted triples | 123 | 123 | **Partial oracle only**; source value + byte span recall 123/145. Name namespaces differ; cannot calculate field F1 or FP |

Another 177 records in the frozen 765-event package were explicitly unscorable
and were excluded from the JSON precision/recall denominators. For the non-JSON
publisher collection, 14 of 30 originals were excluded from scored assertions
under their preserved source-qualified status.

Pinned source SHA and reference provenance are enforced by the dedicated
independent evaluators; original private event values are never emitted into
tracked source, reporting or CI logs:

- `scripts/verification/field_accuracy_generalization_blind_20261022.py`
- `scripts/verification/field_accuracy_publisher_w3c_20261022.py`
- `scripts/verification/field_accuracy_nonjson_publisher_20261022.py`

Corresponding aggregate-only JSON reports are in this directory.

**Important caution:** six SOURCE_PARSED publisher records lacked one or more
publisher-asserted exact source triples. This is an evidence-backed review
signal, not proof of a common grammar bug or independently validated
manufacturer-wide false-complete rate: the asserted oracle is partial and
some publisher field namespaces differ from the engine's original tree.
It must not be dismissed, but neither should a speculative manufacturer
regex/semantic fix be applied without a reproducer and complete truth.

The 588 qualifying JSON cases all stayed fully correct and unchanged by the
MDL proxy. The independent publisher and W3C examples also had no selected
field change. Candidate-pool cardinality one means this is **not** an
informative multi-hypothesis A/B test of the score's ability to discriminate
genuinely competing parsers.

Latency observations come from a shared development host, not a native
runtime throughput benchmark, production SLA or calibrated overhead claim.
There are insufficient independently varying manufacturer clusters to
calculate a meaningful manufacturer-level confidence interval.

## ACC-3: low-shot residual inference, no new engine

`scripts/verification/lowshot_role_shadow_20261022.py` uses the **existing**
`structural_funnel.learn_funnel_hypotheses` and
`bounded_funnel.run_funnel_event`, with training sets of 3, 5 and 10
disjoint self-authored synthetic Snort-like examples, four held-out examples,
and two negative source controls.

Each training size produced 25 additional source-backed claim occurrences
across its six evaluation records, no baseline claim loss, and no promotion
of an incomplete event to SOURCE_PARSED. These are **unscored proposed spans**,
not 25 independently correct new security fields. The experiment does not
justify admission into normalization or generated native DRAFT outputs.
Unknown-vendor/generalization gains remain unverified.

## ACC-4: role inference with evidence and abstention

`runtime/multipass/role_evidence_shadow.py` implements a deliberately small,
**offline review-only** directional role evidence prototype. It requires a
standalone IPv4:port directional-arrow IPv4:port structure, validates IP
octets, numeric port limits and exact source byte locations, and abstains
on ambiguous, embedded, malformed or unsupported patterns.

Eight self-authored synthetic tests yielded two *review-only* role suggestions
and six abstentions, zero test role errors, zero source span errors and no
change to automatic mapping. This cannot be reported as real-vendor wrong-role
rate or as an implemented product feature. Existing official Stellar Cyber
**7.0-only** alias and type/ambiguous-mapping protections remain authoritative.
Do not invent source/destination roles without independently qualified
directional evidence.

## ACC-5 and promotion decision

No rationale for a new offline LLM-synthesis engine, giant grammar-miner
dependency or event-per-request runtime LLM emerged from these trials.
ACC-5 is **CONDITIONAL / NOT TRIGGERED** rather than incomplete implementation.
Existing ChatGPT Assisted Parser stays user-triggered, with a deterministic
review/validation and DRAFT compiler boundary.

**Integration gate is not met**: there is no independent, held-out,
multi-candidate case with demonstrated precision/F1 improvement and zero
regression. Continue the currently active user-interface acceptance separately;
do not allow this research lane to block it. Only reopen the accuracy research
on a new reproducible misparsed field/value/byte position or independently
qualified competing parser candidates that can be measured against a frozen
manufacturer/template holdout.

## Reproduction

The pinned independent data lives in preserved private development-server
directories and is intentionally NOT vendored into GitHub. Synthetic
self-contained smoke/regression remains runnable through standard CI:

```bash
python3 -m unittest discover -s tests -p 'test_field_accuracy_shadow_20261022.py' -v
python3 -m unittest discover -s tests -p 'test_accuracy_external_lowshot_role_20261022.py' -v
python3 scripts/verification/lowshot_role_shadow_20261022.py --mode all
```

For private independent oracle runners, use each script's `--help` to supply
the existing locally pinned oracle/source paths. All are read-only and emit
only aggregate/digest evidence. Never publish private log source values,
customer identifiers or fabricated manufacturer performance.
