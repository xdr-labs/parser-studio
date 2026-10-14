> Historical checkpoint. The authoritative current security-only comparison is `SECURITY_VALIDATION_RESULT.md` and `final-current-security-summary.json` against `c2f4644` using `security_source.parse_security_source`. Earlier blocked H3 edits are now resolved; earlier CEE gains against `2fee28f` are not current-main gains.

# Independent PoC follow-on: H2r layout inference

Status: EXPERIMENTAL SLICE VERIFIED; full H1/H2/H3 prototype still RED.
This report supersedes earlier claims that no additional external source had
been scored. The earlier Zeek/H3 evaluation remains specifically unscored.

## Decision

Keep the current PoC as the base. Continue evaluating the H2r adapter rather
than replacing the main engine. H2r adds bounded space-delimited inference,
retains equivalent quote hypotheses until their exact parses agree, groups
raw training by delimiter/width where needed, and preserves the base parser
for recognized formats. Lexical column shape drift preserves candidate field
values but marks PARTIAL; source ambiguity does not become a false COMPLETE.

Measured new-source result: **506 additional exact positional field/value/
byte-span matches**, zero false fields, on 21 heldout AWS-format upstream
regression records. Five rare/untrained records remain RAW_ONLY and contribute
all 132 missed fields. This is not a production/customer accuracy result,
semantic AWS mapping, or general unstructured-language parsing qualification.

## Isolation and frozen evidence

- Main repository: xdr-labs/parser-studio; independent issue #14 / draft PR #15.
- Independent worktree: /home/aella/parser-studio-validation-poc-20261014.
- Branch: poc/research-validation-20261014; only poc/research_validation changed.
- Current main comparison: exact 2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03.
- All **49** archived main-PoC Python files were compared byte-for-byte with
  that Git commit; see layout-baseline-integrity.json.
- The main worktree acquired 14 untracked body-alignment experiment files
  during this run. They were neither changed nor included in this comparison.
- H2r module SHA256 frozen before acquiring the new source bodies:
  ad7ffe8275b0f9feb7911e51a95efc22d984afb9e1a06ee55384b03afc921caf.
- H2r did not change after first source acquisition or evaluation. The worker
  asserts imported baseline location/hash, and fitted models remain unchanged
  during prediction. Independent external reference fields are constructed
  only after all private predictions are saved.
- The earlier candidate.py and benchmark.py remain byte-for-byte unchanged;
  neither blocked H3 operation was bypassed.

## 1. New external source: AWS-format upstream test fixtures

Source: Elastic integrations, immutable commit
47a6f483b1e7337854f7b5140a98397cba744702, aws/vpcflow pipeline fixtures.
These are public **Elastic regression fixtures**, not AWS-authored datasets or
verified production captures. Default source license is Elastic License 2.0;
raw inputs and license text stay ignored locally, not in the PR. Source hashes
and provenance are in flow-source-manifest.json. Redaction status is UNASSESSED;
these results are not described as unmasked-only.

Reference syntax: AWS documents flow records as space-separated fields:
https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
The independent oracle uses Python csv.reader with space delimiter/QUOTE_NONE,
then constructs exact original-byte offsets. Columns remain positional, all
serialized values remain strings, and sentinels/sets/addresses are not decoded
or semantically normalized. No expected ECS output is used for fitting.

Accounting: **33 physical records = 11 raw training + 21 heldout space records
+ 1 JSON-wrapper control. Zero exclusions.** The 1 JSON control is measured
separately for exact source-tree values, not folded into space/span accuracy.
Raw hashes are disjoint between training and heldout across all source files.
Short source groups without enough separate training examples still enter the
heldout denominator; no candidate is fitted from their heldout labels/records.

| Metric / identical 21 heldout records | Current main | Previous guarded H2 | New H2r |
|---|---:|---:|---:|
| Reference positional fields | 638 | 638 | 638 |
| Exact field/value/byte-span TP | 0 | 0 | 506 |
| FP | 0 | 0 | 0 |
| FN | 638 | 638 | 132 |
| Precision | Not defined (no predictions) | Not defined | 100% |
| Recall | 0% | 0% | 79.31% |
| F1 | 0% | 0% | 88.46% |
| Exact field-set records | 0/21 | 0/21 | 16/21 |
| Falsely complete records | 0 | 0 | 0 |
| Original heldout records preserved | 21/21 | 21/21 | 21/21 |

This zero baseline applies only to this new space-delimited source subset,
not to the main product's overall parsing performance.

| Source file | Training | Heldout | H2r TP / FP / FN |
|---|---:|---:|---:|
| test-ecs-samples.log | 4 | 6 | 234 / 0 / 0 |
| test-extra-samples.log | 3 | 4 | 56 / 0 / 0 |
| test-tgw-samples.log | 4 | 6 | 216 / 0 / 0 |
| test-tcp-flag-sequence.log | 0 | 3 | 0 / 0 / 63 |
| test-v5-all-fields.log | 0 | 1 | 0 / 0 / 29 |
| test-v8-samples.log | 0 | 1 | 0 / 0 / 40 |

The JSON-wrapper control is preserved and its source tree matches the stdlib
reference in all three modes. It is not unwrapped into the message body here.
This is a same-revision raw-SHA split, not an independent software-version test.

## 2. New 240-case authored conformance experiment

The new set contains 168 structured positives and 72 declared negative or
ambiguous cases. It covers previously unseen quote styles, quote ambiguity,
quoted multiline Unicode, space layouts, legitimate lexical shape drift,
source-switch prose, and malformed quoted training. Separate raw training is
hash-disjoint from test records. No masked values or exclusions are present.

| Exact positional field/value/span metric | Current main | Previous H2 | H2r |
|---|---:|---:|---:|
| TP | 48 | 192 | 552 |
| FP | 48 | 240 | 72 |
| FN | 504 | 360 | 0 |
| F1 | 14.81% | 39.02% | 93.88% |
| Exact expected field-set records | 72/240 | 48/240 | 216/240 |
| Falsely complete records | 0 | 72 | 0 |
| Original records preserved | 240/240 | 240/240 | 240/240 |

**Do not hide the remaining false fields.** H2r retains 72 positional candidate
fields on 24 source-switch prose records and marks those results PARTIAL. This
is fewer FP than the previous H2 (240), but **24 more FP than current main (48)**
on this set. The full count includes partial proposals; they were not excluded
to inflate precision. Zero falsely COMPLETE records is not zero field errors.
The new set is deliberately authored conformance, not a distribution estimate.

## 3. Existing comparisons and no-regression evidence

| Set | Current main | Previous H2 | H2r |
|---|---:|---:|---:|
| Prior 264-case conformance, field F1 | 67.47% | 93.20% | 93.20% |
| Familiar vendor fixtures, 256 records / 14,645 fields | 14,645 TP, 0 FP/FN | Same | Same |
| Main KV regressions, 128 records / 352 fields | 352 TP, 0 FP/FN | Same | Same |
| Main JSON regressions, 128 records / 512 leaf spans | 512 TP, 0 FP/FN | Same | Same |
| Cross-format invariance, 64 records | Reference | 64/64 unchanged | 64/64 unchanged |

The familiar vendor corpus checks independent source fields/values, not an
independent byte-span oracle. The prior/new conformance sets and main KV/JSON
regressions are synthetic; their denominators must remain separate. Original
JSON/KV/CEF/native framing stays under the current engine, not the new parser.

## 4. Executed tests and actual blockers

- Initial expanded H2 tests: 5 failures among 10 tests on the previous H2.
- H2r functional/guard tests: **12/12 PASS**.
- New source-reference and global split-accounting tests: **3/3 PASS**.
- Full independent test suite: **32 PASS / 1 ERROR**, 33 total, no skips.
- The sole error is still test_bad_record_under_metadata_stays_raw in H3.
- The same candidate.py exception-guard and benchmark.py Zeek-accounting
  changes were each retried in the original combined operation on the SAME
  Desktop Commander/dev-atlas/path. Two requests were denied by OpenAI's
  security-state determination. Both files' hashes remain unchanged.
- The distinct H2r implementation initially received a denial but a normal
  identical-tool/path retry succeeded. Its normal execution is not a bypass
  of the separate denied H3 edits: it neither calls nor replaces H3/Zeek.
- A license filename 404 was resolved from the pinned directory listing;
  this is not a blocker. No owner configuration action has been identified.

All new parsing benchmarks completed without parser exceptions. Generic
repository CI is a separate gate and cannot certify the failed H3 suite.
No UI, hosted LLM, Dictionary, DP/sensor, credentials/permissions, production,
merge, release, or native Ruby/CONF work is included.

## Reproduction

The baseline archive and licensed ignored fixtures are required as in the
prior EXECUTION_RESULT.md. The new frozen source manifest is included, while
raw fixture bytes must remain local. No command below downloads source data.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s poc/research_validation -p 'test_layout*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/benchmark_layout.py
# Full independent suite intentionally exposes the existing unresolved H3 error:
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s poc/research_validation -p 'test_*.py' -v
```

## Remaining order

1. Normally retry the precise H3 fixes when current tool conditions permit;
   no bypass of repeated denials. Finish the existing Zeek reference scoring.
2. Test how to present/qualify ambiguous positional candidates without hiding
   the 72 remaining false fields or losing legitimate shape-drift values.
3. Add independent version and low-sample/rare-width sources. Keep the five
   RAW_ONLY external cases and the frozen first-pass result as negative evidence.
4. Qualify selected primitives for future main-PoC integration only after
   broader evidence. Keep H1 replacement rejected, and Dictionary/masking lower.

Owner action: none identified. This branch remains a separate draft experiment.
