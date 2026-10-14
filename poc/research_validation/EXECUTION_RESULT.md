> Historical checkpoint. The authoritative current security-only comparison is `SECURITY_VALIDATION_RESULT.md` and `final-current-security-summary.json` against `c2f4644` using `security_source.parse_security_source`. Earlier blocked H3 edits are now resolved; earlier CEE gains against `2fee28f` are not current-main gains.

# Independent Parser Extraction Validation — Executed Results

> Follow-on checkpoint: see NEXT_POC_RESULT.md for H2r and the newly completed AWS-format source evaluation. The original Zeek/H3 evaluation below remains specifically incomplete. Historical results below are preserved.

## Decision

**Keep the current PoC. Selectively advance H2 (raw-only multi-sample delimiter inference), not a wholesale replacement with the new prototype.** On the authored boundary/delimiter suite, the current engine plus guarded H2 improves exact native-key/value/byte-span F1 from **67.47% to 93.20% (+25.73 percentage points)**. Existing main-PoC KV and JSON regressions and the known 256-record source corpus remain intact.

This is measured improvement on deliberately constructed conformance cases, **not a demonstrated general improvement on unseen real-vendor logs**. Additional external Zeek logs were acquired, but their field comparison did not complete. Full H1/H2/H3 prototype acceptance is FAIL because a malformed-metadata exception remains. No product integration or release is claimed.

## Isolation and comparable versions

- Owner explicitly requested a separate verification PoC, implemented directly by CHATGPT_CHAT in Chat mode on dev-atlas.
- Independent worktree: `/home/aella/parser-studio-validation-poc-20261014`.
- Independent branch: `poc/research-validation-20261014`; changed files are only under `poc/research_validation/`.
- Initial actual local/remote baseline: `acc3a903e19597af44635b243fa4be3b4949e35f`.
- The ongoing main PoC concurrently committed its KV and JSON fixes. The comparison was therefore rerun against **`2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03`**, using an isolated exact-commit archive.
- Frozen experimental module SHA256: `cd4691e09c3ba26f000fc4d685e1e43706f035bff8bf866e5d7bad4f8b5c72a6`. The denied H3 fix was not applied. This module did not change after external acquisition.
- No tracked main-engine file was modified in this validation branch. The original untracked KV test was subsequently changed and committed by the ongoing main lane; the original worktree was not reset, cleaned, stashed, or overwritten here.

## A. Current baseline vs recommended guarded H2

**264 authored unmasked evaluation records, 936 expected field occurrences, zero exclusions.** There are 216 positive grammar cases and 48 malformed-tail/prose cases. H2 uses 32 distinct raw training records (eight per comma, semicolon, pipe and tab dialect); training and evaluation raw hashes are disjoint. The caller supplies homogeneous source batches. This is not a learned mixed-source clustering/router test.

| Measure | Current PoC 2fee28f | Current PoC + guarded H2 |
|---|---:|---:|
| Correct key/value/byte-span fields (TP) | 504 | 864 |
| Incorrect fields (FP) | 54 | 54 |
| Missed fields (FN) | 432 | 72 |
| Precision | 90.32% | 94.12% |
| Recall | 53.85% | 92.31% |
| Field F1 | 67.47% | 93.20% |
| Exact expected field-set events | 154/264 | 226/264 |
| Falsely complete events | 0 | 0 |
| Original records preserved | 264/264 | 264/264 |

The measured gain is **360 additional correctly extracted fields and 72 additional exact field-set events**. The FP count does not improve. Most new coverage is semicolon/pipe/tab data that the existing single-record parser does not structurally handle. The source keys are retained, and unnamed table columns remain positional; no Dictionary/type semantics are inferred.

Known remaining gaps include container-shaped KV values and comma-containing prose. A raw-only/partial outcome and raw preservation are never relabeled as successful field extraction.

## B. Non-regression against main-PoC and actual-source data

| Independent comparison set | Records / expected fields | Current PoC | Current + guarded H2 |
|---|---:|---:|---:|
| Existing pinned vendor source fixtures | 256 / 14,645 | 14,645 TP, 0 FP, 0 FN | 14,645 TP, 0 FP, 0 FN |
| Main PoC's newly authored KV regressions | 128 / 352 | 352 TP, 0 FP, 0 FN | 352 TP, 0 FP, 0 FN |
| Main PoC's newly authored JSON leaf-span regressions | 128 / 512 | 512 TP, 0 FP, 0 FN | 512 TP, 0 FP, 0 FN |
| Cross-format routing invariance probes | 64 | Reference output | 64/64 exactly unchanged |

The 256-record source corpus is already familiar to the main PoC. Independent stdlib decoders check native fields and values, but that corpus has **no independent byte-span oracle in this comparison**. Its source redaction status is unassessed; it is not an unmasked-only performance figure. The KV/JSON sets are synthetic regressions authored by the main lane, not independent vendor/version holdouts. JSON leaf-span coverage and logical source identities are reported separately in the JSON evidence.

The H2 adapter first preserves recognized JSON, KV, CEF/LEEF and framed grammars, even when partially parsed. It only considers a learned dialect for eligible unknown/unqualified-delimited input. A rejected dialect proposal returns the original base result. This was implemented and checked because unconditional application of a table dialect changes existing-parser results on the 64 mixed-format probes.

## C. Rejected alternatives and ablation

| Variant | New 264-record suite F1 | Main KV regression F1 | Main JSON leaf-span F1 | Decision |
|---|---:|---:|---:|---|
| Current main 2fee28f | 67.47% | 100% | 100% | Retain as base |
| Frozen full candidate on old acc3a90 base | 98.73% | 93.02% | 89.66% | Reject wholesale replacement |
| Current main + H1 + H2 | 98.73% | 93.02% | 100% | Reject general KV replacement |
| Current main + guarded H2 only | 93.20% | 100% | 100% | Preferred next-validation slice |

H1 improves container/quote cases in this lane's authored set, but loses **32 correct fields and adds 16 false fields** on the main lane's escaped-bare-space cases (16 affected events). It must not replace the current KV scanner globally. The frozen candidate also misses 96 JSON leaf spans because its old base predates the concurrent JSON-path fix. These regressions are retained rather than hidden behind the highest aggregate score.

The historical first comparison against acc3a90 was 49.56% -> 98.73%. That is **not the final current-PoC gain**; the latest comparison above takes precedence.

## D. External evidence and explicit incomplete work

Six SHA-pinned first-party Zeek regression-output log files were acquired from `zeek/zeek` commit `a7e71a217b670e09e43b75fccfc3a96f04cbec2a`: connection, DNS, HTTP, extended connection fields, TLS and IPv6 DNS examples. They contain **187 physical records = 127 data records + 60 reference-classified metadata/preamble records**. All raw files and license text remain ignored in `.cache/external/`; only source URLs, hashes and aggregates may be committed.

The first external run stopped at a metadata-accounting assertion: every file has one BTest provenance preamble before the Zeek separator declaration. The candidate retains those six lines as RAW_ONLY records instead of classifying them as metadata. This is a classification difference, not evidence of dropped data or scored field accuracy. The candidate's actual data fields have **NOT BEEN REFERENCE-SCORED** in the external benchmark.

Two narrow modifications were each denied by OpenAI's security-state check, including one normal same-tool/device/path retry after successful connectivity verification:

1. `candidate.py`: handle malformed declared-metadata records without an uncaught exception; the failing unit test remains.
2. `benchmark.py`: explicitly account for BTest preambles instead of terminating the external evaluation at the metadata-equality assertion.

No alternate tool, host, encoded command, or replacement path was used to perform those denied modifications. Independent permitted comparisons against the original and current baselines continued. **Do not treat this as an external Zeek PASS.** The existing `comparison-summary.json` is the successful pre-acquisition snapshot; use this report and `external-status.json` for the later external state.

## E. Executed verification

- Frozen main-engine affected suite: **63 tests PASS**.
- New metric/scorer contract suite: **5 tests PASS** (occurrence accounting, wrong-span FP/FN, exceptions, disjoint training).
- Full candidate unit suite: **12 PASS / 1 ERROR** out of 13. The error is the explicit malformed-metadata safety regression; it is not skipped or reported as green.
- CSV scanner differential checks within the candidate tests: **320 generated cases** agree with Python `csv.reader` across four delimiters and two quoting dialects.
- Latest-current comparison: isolated subprocesses assert actual imported parser module paths and SHA256 hashes. See `current-head-comparison.json`.
- Selective H2 verification: 264 authored cases, main KV/JSON 128+128, 64 cross-format invariance cases, and 256 existing source records executed. See `selective-h2-summary.json`.
- No hosted LLM calls, Dictionary normalization, UI changes, DP/sensor operations, source fixture redistribution, native Ruby/CONF qualification, production, merge or release.

## F. Reproduction

From this independent worktree, with the exact baseline archive and the already licensed local fixture cache present:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/compare_latest.py
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/verify_selective_dialect.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s poc/research_validation -p test_benchmark.py -v
```

For a fresh checkout, create `.cache/latest-baseline/` under this research directory and extract `git archive 2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03 poc/vendor_engine` into it. Copy only the already permitted raw/gold fixture cache into that archived engine's `.cache/`; do not redistribute the fixtures. The code performs no automatic fixture download in these verification commands.

The full candidate test suite is intentionally still RED. The original `benchmark.py` now reaches the documented external assertion because the external files exist; that path needs the explicitly recorded normal retry before it can be completed.

## Remaining order

1. Retry the two recorded blocked edits normally under newly permitted conditions; do not bypass repeated denials.
2. Complete external reference accounting/scoring and then unseen vendor/version/rare-source evaluation for guarded H2.
3. Broaden delimiter quote/escape/multiline and mixed-source grouping tests. Preserve base-parser-first admission.
4. Consider a bounded container-KV extension only while retaining the current escaped-bare-value behavior.
5. Only after evidence supports adoption, integrate selected primitives into the main PoC. Dictionary normalization and masked-input work remain lower priority.

User configuration action: none has been identified. The verified blockers are the two tool security-state denials, not missing owner approval, host connectivity, or GitHub access.
