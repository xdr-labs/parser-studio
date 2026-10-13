# Extraction-First PoC — Source Field and Residual Template Evidence

Status: **RESEARCH ONLY; no Parser Studio product integration or native/Stellar verification.**

## Owner priority / definition of success

**P0: extract source fields correctly, preserve their native vendor keys/positions,
exact values, source byte spans and every original record**. No user needs to
identify JSON/KV/Syslog/CEF/LEEF/CSV or write Regex on the supported path.
If meaning is unknown, it remains a vendor field. A parser that returns some
values while losing or misidentifying others is PARTIAL, not a full pass.

**P1: optional Stellar Cyber Dictionary normalization** after verified parsing.
No Dictionary mapping, target artifact compiler, DP write, sensor send, UI
or external LLM is part of this research.

## A. Source-structure extraction evidence

- Eight SHA-pinned upstream research datasets from Fortinet/PAN-OS/Trellix/
  Trend Micro: 256 events, 14,645 syntactically extracted source values.
- Every source event preserved, 256/256 with full local structural parsing;
  zero residual bytes on this limited, known-format corpus.
- Independent standard-library JSON/CSV/KV decoding agrees on 256/256 events.
  **The new exact source-field benchmark also compares every original field
  path, type, and value against these independent stdlib source decoders:
  14,645 TP / 0 FP / 0 FN, Precision/Recall/F1 100% on this corpus.**
  This is ground truth for the *supported syntax in these eight familiar
  source fixtures*, NOT an unseen vendor/version generalization test or a
  semantic ECS/Stellar field-mapping qualification.
- Four distinct research-only CC0 Log Zoo real-source sample events parsed
  structurally. They remain in ignored local `.cache`, never redistributed.
- Original product `createDraft()+preview()` unconfigured event extraction
  was 80/256 on the same 256 events. That is NOT a fully configured engine
  benchmark and cannot be used as a universal 3.2x product claim.

## B. Genuine annotated-variable evaluation, not just template match

**Research reference:** [Loghub](https://github.com/logpai/loghub), Zhu et al.,
*Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*,
ISSRE 2023. Loghub's LICENSE permits research/academic work with attribution and
requires inclusion of its license in dataset copies. Raw logs and annotated
template CSVs stay in separately ignored `.cache/loghub`; **do not bundle them
or derived literal templates in commercial parser packages without rights
review.**

Pinned Loghub master revision `dd61d0952749ee7963bde24220d1be5ede023033`,
two families (Linux/Apache, 2,000 raw lines each). The paired annotated
`EventTemplate` files each contain 2,000 aligned rows; all 4,000 template
strings independently fully match their referenced `Content`. Their
wildcard source-value positions are a **third-party template-reference
benchmark**, not full vendor-field names, ECS labels or the Stellar Dictionary.

Train/test split uses raw-content SHA grouping so identical raw records do
not leak into test. Only training source bodies fit Drain3. Its template
candidate grammar is frozen before heldout reference evaluation. Same upstream
data revision/format across train and holdout: NOT a software-version holdout.
Empty annotated wildcards are not countable source-value spans.

| Algorithm / matched reference variable spans | Holdout | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Unsupervised Drain3 raw residual candidate | 1,581 | 518 | 73 | 2,620 | 87.65% | 16.51% | 27.78% |
| Drain3 + strict source-byte anchor alignment | 1,581 | 744 | 73 | 2,394 | 91.06% | 23.71% | 37.62% |
| LogPai Spell (unlabeled train-only token alignment) | 1,581 | 572 | 1,227 | 2,566 | 31.80% | 18.23% | 23.17% |
| Drain3 + *entire* unlabelled message context | 1,581 | 1,110 | 1,615 | 2,028 | 40.73% | 35.37% | 37.86% |
| **Pre-labeled, verified grammar retrieval** | **1,581** | **3,073** | **0** | **65** | **100%** | **97.93%** | **98.95%** |

- There are **3,138 independently annotated, non-empty variable spans** in
  the shared residual holdout. Merely matching a Drain3 template on 1,540
  messages was NEVER counted as successful variable extraction.
- Full-message Drain3 mining improves recall but generates **1,615 false
  reference-template spans** and is NOT an acceptable replacement.
- **Spell (LogPai, pinned `d9d4180784cde9afef990eeeb458591011933f9b`)**
  was run with the same raw-SHA train/holdout split and source byte scoring,
  isolated Apache-2.0 algorithm implementation and optional research-only
  pandas/regex dependencies. Its token-normalized templates score **F1 23.17%**
  (1,227 false variable spans), worse than conservative Drain3 anchoring.
  **REJECT** Spell for this source-field extraction use case. Its published
  clustering/FTA benchmark scores measure a different outcome and are not
  comparable with our original-byte extraction F1.
- A train-only varying-KV-island probe on full Linux message bodies identified
  179 gold-template variable spans and 179 additional non-template spans.
  Joining those with raw Drain3 proposals raised recall but also false
  captures; **do not ship this unqualified union**. Static `key=value` values
  are still legitimately parsed original vendor fields even when Loghub's
  template benchmark does not label them as variable slots.
- The marked retrieval result uses **24 reusable grammar profiles created
  from Loghub's *training-set EventTemplate annotations*** (minimum two
  distinct train samples, exact provenance, stable literal anchors). It routes
  1,523/1,581 heldout messages, abstaining on unsupported/ambiguous samples.
  Apache reference F1 99.12%; Linux 98.86% on this limited same-revision set.
- This **98.95% is NOT no-label automatic parsing**. It is a proof that
  retrieval from verified permitted parser assets (or user-approved templates)
  can avoid manual Regex authoring for familiar log grammars. These templates
  are not cleared for bundling in the commercial product.

Commands (run on authorized dev-atlas, with ignored pinned fixtures already
present; none sends events to a DP/sensor or calls a hosted LLM):

```bash
python3 poc/vendor_engine/corpus.py
python3 poc/vendor_engine/evaluate_source.py
python3 poc/vendor_engine/benchmark_source_field_gold.py
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 poc/vendor_engine/benchmark_residual_gold.py
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 poc/vendor_engine/trusted_template_reuse.py
# Optional licensed-research comparison; requires local ignored logparser
# Apache-2.0 Spell checkout and isolated optional dependencies.
PYTHONPATH=poc/vendor_engine/.cache/logparser:poc/vendor_engine/.cache/logparser_deps python3 poc/vendor_engine/benchmark_spell_source.py
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 -m unittest discover -s poc/vendor_engine -p 'test_*.py' -q
```

## Implementation decision and remaining product gates

**Adopt extraction-first retrieval plus deterministic parsing as the PoC's
preferred architecture, conditional on independent evidence**:

1. Trusted deterministic envelope/body formats: JSON, quoted KV, positional
   CSV with qualified column boundaries, CEF, LEEF, RFC3164/RFC5424. Preserve
   every vendor/unknown field; no normalization prerequisite.
2. Infer vendor/subtype grammar signatures from the raw sample; reuse an
   explicitly licensed/owner-approved, regression-qualified parser profile
   if its framing and exact source anchors match. Validate no collision with
   other qualified profiles; unsupported variants stay PARTIAL.
3. Novel residual text: bounded train-only grammar induction, source-byte
   alignment, independent positive/negative and metamorphic tests. Never
   promote a Drain3 template match or arbitrary `<*>` to a verified field.
4. Only when extraction passes: optional Stellar Dictionary mapping. Unknown
   names and unsupported roles stay intact as original vendor values.
5. Before product completion, separately confirm permitted source-license
   inventory, genuinely new manufacturer/version holdout, field-level gold
   precision/recall (not merely template parameter agreement), error and
   source-byte accounting, native Ruby+CONF differential tests and
   authorized Stellar target qualification.

**Highest unfinished engineering problem:** genuinely *unlabeled*, previously
unknown unstructured logs still show **37.62% annotated-variable F1** with
conservative automatic source-aligned Drain3 capture. Do not advertise the
trained 98.95% as the solution to that open-world problem. Continue exploring
deterministic variable-boundary induction, conservative repair and richer
copyright-cleared independent data without misleading performance claims.
