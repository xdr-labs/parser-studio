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

**Lowest priority: already-masked/redacted/anonymized input.** Preserve each
visible token and its source span, recognize masking best-effort, and never
recover or fabricate hidden values. A Loghub annotation wildcard or Drain3's
internal IP/NUMBER representation is not evidence that a raw input is redacted.
Do not present an unassessed corpus as an unmasked-only KPI, or exclusions as
successful extraction. Existing safety/no-data-loss tests remain mandatory.

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
| Drain3 + strict source-byte anchor alignment (historical unmasked) | 1,581 | 744 | 73 | 2,394 | 91.06% | 23.71% | 37.62% |
| **Drain3 corrected IP/NUMBER mask + typed byte alignment** | **1,581** | **821** | **31** | **2,317** | **96.36%** | **26.16%** | **41.15%** |
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
- In the original Drain3 research prototype, the IP/number `MaskingInstruction`
  regexes were **doubly escaped and matched no actual IPv4/numeric tokens**.
  We preserved the prior broken configuration as an explicit historical baseline,
  corrected regexes in a separate `typed` mode and taught the source-byte
  aligner the actual Drain3 0.9.11 mask labels `<IP>`/`<NUMBER>`.
  Independently bounded/malformed/type test coverage PASS. On the *same
  previously examined* Loghub holdout, the corrected mode increased F1
  **37.62% → 41.15%** while reducing FP **73 → 31**; no cross-family
  template match in the sample. Multiple mask variants were inspected on
  this holdout, so this result is **exploratory, not new untouched
  validation**. The 41.15% F1 is still far below a cold-start product gate.
- **Separate, previously unused source families (first prospective comparison):**
  pinned Loghub **OpenSSH + Proxifier**, 4,000 original source records with
  associated reference templates kept ignored. Each family was trained
  using raw-only content hash-disjoint samples, and labels were first read
  AFTER fitting. On **1,578** held-out events and **5,882** independently
  annotated nonempty variable spans: legacy Drain3/alignment **1,852 TP /
  2,322 FP / 4,030 FN (P44.37%, R31.49%, F1 36.83%)**; corrected typed
  mask/alignment **2,608 TP / 3,441 FP / 3,274 FN (P43.11%, R44.34%, F1
  43.72%)**. Crucially, OpenSSH improved F1 **45.61% → 71.30%** while
  unframed Proxifier **degraded 31.94% → 26.75%**. Therefore the typed
  setting is **NOT qualified as a globally safe default**; frame/grammar
  admission and false capture safeguards must be validated *prospectively
  again* on other unexposed source families. Same vendor source revision
  train/test, not a new software-version holdout.
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
# Corrected typed-mask experiment is published only as exploratory evidence
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 poc/vendor_engine/publish_extraction_summary.py
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 poc/vendor_engine/trusted_template_reuse.py
# Optional licensed-research comparison; requires local ignored logparser
# Apache-2.0 Spell checkout and isolated optional dependencies.
PYTHONPATH=poc/vendor_engine/.cache/logparser:poc/vendor_engine/.cache/logparser_deps python3 poc/vendor_engine/benchmark_spell_source.py
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 -m unittest discover -s poc/vendor_engine -p 'test_*.py' -q
```

## C. Mac/Hadoop framing admission — negative experiment completed

The frozen hypothesis selected corrected typed extraction only when the raw
record passed the existing deterministic BSD header scanner; other records
used legacy extraction. Both models were trained from raw content only,
BEFORE reading the independent labels. Parameters and the historical outcome
were not changed to improve this failed hypothesis.

- Pinned Loghub revision: `dd61d0952749ee7963bde24220d1be5ede023033`.
- 4,000 raw records: 2,407 training and **1,593 total heldout records**.
- **1,579 reference-scored events / 4,482 annotated nonempty variable spans**.
- **14 excluded Mac references**: 12 `REFERENCE_TEMPLATE_MISMATCH`, two
  `REFERENCE_TOO_LARGE`. Exclusions are not successes and no original record
  is dropped. Hadoop: 794/794 scored. Mac: 785/799 scored.
- Models and source slices are audited before reference reads, training and
  holdout raw hashes are disjoint, and frozen model digests remain unchanged
  after scoring. Published artifacts contain aggregate counts and hashes,
  not raw events, gold labels, captures or learned literal templates.

| Fixed mode | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy | 121 | 1,611 | 4,361 | 6.99% | 2.70% | 3.89% |
| Global typed | 1,316 | 6,341 | 3,166 | 17.19% | 29.36% | 21.68% |
| BSD-header admission | 381 | 1,649 | 4,101 | 18.77% | 8.50% | 11.70% |

**Decision: REJECT header-only automatic grammar admission.** An identifiable
header does not establish correct variable boundaries in the message body.
No setting above is promoted to a product default. This is annotated-variable
source-span agreement, not complete vendor-field accuracy or normalization.
Source redaction status has NOT been assessed, so these historical mixed-source
metrics are not labeled unmasked-only. Same upstream revision train/holdout
is not a genuinely new software-version test. Any later Mac/Hadoop tuning
must be labeled exploratory, not a fresh prospective evaluation.

Reproducible qualified artifacts: `benchmark_framing_admission.py`,
`test_benchmark_framing_admission.py`, `framing-admission-summary.json` (v0.2
corrects the original ambiguous holdout denominator without changing TP/FP/FN).

```bash
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 poc/vendor_engine/benchmark_framing_admission.py
PYTHONPATH=poc/vendor_engine/.cache/drain_deps python3 -m unittest discover -s poc/vendor_engine -p 'test_benchmark_framing_admission.py' -v
```

## D. Ordinary unmasked-source regressions — calendar and lexical boundaries

After the negative experiment was committed, source inspection and new RED
regressions found (1) missing November in the BSD month table, (2) a URL query
or filename suffix being misidentified as a vendor key, and (3) nested key-like
strings inside quoted prose or malformed quoted values being extracted as
new fields. Six failing subcases were reproduced before the fix.

The engine now accepts all 12 valid months while still rejecting impossible
dates; key discovery requires a real token/delimiter boundary and skips quoted
regions in one bounded pass. An owning quoted vendor value is preserved as one
value, including embedded equals signs, Unicode, duplicates and exact source
spans. Unresolved prose/malformed tails remain residual in the unchanged raw
record. No Dictionary or raw-redaction-specific optimization was introduced.

**Controlled synthetic regression evidence, NOT a new-vendor accuracy claim:**
`benchmark_unmasked_boundaries.py` runs the exact committed baseline
`24d232178a11b59db67afedd198374c5fdf702c8` and candidate in isolated Python
processes. Gold paths, string values and byte spans are constructed alongside
the input, independently of parser output. All **84 events / 312 source
fields** deliberately contain visible unmasked values: zero masked, unassessed
or excluded events. Both retain 84/84 original records.

| Same regression corpus | TP | FP | FN | Field/span F1 | Exact field tree + all spans |
| --- | ---: | ---: | ---: | ---: | ---: |
| Committed baseline | 297 | 76 | 15 | 86.7153% | 34/84 events |
| Corrected lexical/calendar boundaries | 312 | 0 | 0 | 100% | 84/84 events |

This focused benchmark proves the reproduced fixes, not open-world parsing,
new manufacturer/version generalization, annotated-variable improvements,
masked-value inference or Stellar/native compatibility. Earlier frozen
Mac/Hadoop and OpenSSH/Proxifier metrics remain historical and unchanged.

```bash
python3 poc/vendor_engine/benchmark_unmasked_boundaries.py
python3 -m unittest discover -s poc/vendor_engine -p 'test_unmasked_source_boundaries.py' -v
```

## E. Direct Java envelope extraction — candidate; reference validation incomplete

The next ordinary-source unit implements **direct bounded envelope fields**,
not the rejected strategy of using header presence to choose a body miner.
Source inspiration is limited to published Apache PatternLayout conventions
and first-party [Spark v1.5.2 configuration](https://github.com/apache/spark/blob/v1.5.2/conf/log4j.properties.template)
and [ZooKeeper 3.4.6 configuration](https://github.com/apache/zookeeper/blob/release-3.4.6/conf/log4j.properties).
No vendor implementation, Loghub template, customer data or normalized
Dictionary mapping is copied into the engine.

`java_source.py` extracts date, time, level and explicitly bounded logger,
thread/context and optional node-ID fields. It keeps two-digit dates as source
strings and does not invent a century or timezone. Unknown prose remains
residual/PARTIAL; recognizing a header never certifies the body, Drain grammar,
Ruby/CONF, Fluentd or Stellar compatibility. Five focused tests (including
invalid dates, missing delimiters, Unicode spans and false-success prevention)
were RED before implementation and pass afterward. Four of the five test
methods failed before implementation; the invalid-header guard already passed.

**First raw-only probe on previously unused source families**, using candidate
hashes frozen BEFORE the new raw files or labels were acquired:

| Source family | Original records preserved | Header proposals | Proposed header fields | Independent reference-scored events |
| --- | ---: | ---: | ---: | ---: |
| Spark | 2,000/2,000 | 2,000 | 8,000 | 0 — pending |
| ZooKeeper | 2,000/2,000 | 0 | 0 | 0 — pending |

All Spark records remain PARTIAL; the full body is not declared parsed.
ZooKeeper's zero-header result is retained as a negative finding, not tuned
away or excluded. The independent reference CSV acquisition/read request was
blocked twice by OpenAI's security-state determination after normal same-tool,
same-device, same-path retry. Both new reference CSV files are confirmed
absent. No alternate tool, host or download route was used to bypass the block.

The local existing-fixture suite passes **138 tests** with this candidate,
but this does NOT qualify independent Spark/ZooKeeper field accuracy. Code is
saved as an experimental PoC candidate; `java-envelope-probe-summary.json`
contains only hashes and aggregates. Raw source, license notice and frozen
private predictions remain in ignored `.cache/`. Redaction status of this
real-source probe is unassessed, so it is not an unmasked-only benchmark.

**Immediate unfinished action:** under current permitted conditions, normally
retry the SAME reference-acquisition/read operation on dev-atlas. On success,
verify raw/reference SHA and row correspondence, score actual header values
and exact byte spans against independent annotations, retain the frozen
first-pass zero-ZooKeeper result, and separately label subsequent adaptation
as exploratory. Do not call any count above TP, precision, recall or F1 yet.
Do not start Dictionary/masking work or repeat completed Mac/Hadoop tests
merely to restart this task.

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
unknown unstructured logs still show **41.15% exploratory annotated-variable
F1** with corrected typed-mask + conservative automatic source-aligned Drain3
capture (historical original 37.62%). Do not advertise the
trained 98.95% as the solution to that open-world problem. Continue exploring
deterministic variable-boundary induction, conservative repair and richer
copyright-cleared independent data without misleading performance claims.

## F. Frozen Java candidate independently reference-scored (2026-10-14)

The previously blocked reference acquisition succeeded on normal same-tool,
same-device, same-worktree retry. Both pinned upstream CSVs are now preserved
in ignored `.cache/loghub`; no credentials, permissions or alternative download
route were used. The historical raw-only probe remains unchanged.

`benchmark_java_headers.py` reconstructs header fields and exact UTF-8 spans
from independent reference columns, never EventTemplate inference or parser
regex reuse. Every annotated header and Content byte must match the source.
The ZooKeeper CSV omits one terminal space in 292 source records: these bytes
are explicitly counted, the raw is unchanged, and no valid header is excluded.
Changed non-whitespace content remains a hard reference mismatch.

**Frozen first-pass results:** all 4,000 records / 4,000 reference-scored /
zero excluded; 20,000 atomic header fields. Spark: 8,000 TP / 0 FP / 0 FN;
ZooKeeper: 0 TP / 0 FP / 12,000 FN. Combined header-only F1 57.1429%.
This validates Spark header positions, not its unstructured body; the original
zero-ZooKeeper result remains a recorded failure. All 4,000 original records
remain accounted. Source redaction is NOT_ASSESSED, so this mixed real-source
benchmark is not presented as an unmasked-only KPI. No masking optimization,
Dictionary mapping, commercial template rights or native/DP qualification is
claimed. The reference-acquisition blocker is resolved, not a remaining gate.

Next: repair actual unsupported Java envelope boundaries and validate atomic
context fields, labeled exploratory after source/reference exposure. Preserve
this frozen result and independently audit any composite context outputs.
