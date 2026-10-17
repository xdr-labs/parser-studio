# Isolated blind source-structure generalization PoC (2026-10-17)

## Decision and scope

Owner priority: increase source extraction correctness through reusable structure interpretation, not vendor-specific escape regexes or an impossible universal-parser claim. This PoC is stacked **only** on Draft PR #43, base SHA `44e606377966e5d9b6c4649ac054ff07c91e9ab2`, in branch `poc/generalization-blind-structural-20261017`.

**No production or product parser integration, native Fluentd/Stellar validation, main changes, DP, sensor, deployment or merge.** The new parser and test-only scorer live under `src/poc` and `scripts/poc`. Existing #29–#43 observations are historical evidence, not relabeled new holdouts.

## Pre-scoring frozen independent cohort

The source URLs, exact upstream Git SHAs and each original file's SHA-256, byte length and license metadata were frozen by `scripts/poc/pinGeneralizationSources.py` in `scripts/poc/generalizationSources.pinned.json` **before evaluating candidates**. Public source repositories (different from previous Elastic original cohorts):

| Family | Revision pinned | Files | Independence / ground-truth qualification |
| --- | --- | ---: | --- |
| FrankHassanabad/suricata-sample-data | `2d94c5d73f0d7b652b2adc13b81806048d08ba18` | 4 | PCAP-derived Suricata alert JSON; sealed source cohort, not live device-certified |
| allamiro/JSON-SYSLOG-TO-CEF | `da4dd154e2393b4921f3305da92e76b6e2288194` | 4 | Apache 2.0 public source examples, development |
| sva-s1/log-zoo | `f61b0d7f345f47349a376629bfc3165752b77ade` | 4 | CEF and Fortinet original samples, sealed but **unscorable** without a complete independent non-JSON field oracle |
| TanayBhatt26/siem-log-parser | `d5a821af51b03a4767aeeb6d7619455a6bfbe606` | 6 | Sample examples, unspecified license, research-only in private local state |

**18 files**, **635,773 bytes**, **18 distinct source SHA-256 hashes**, zero same-file duplicates; none originate in the previously used `elastic/integrations` source repository. Public pins manifest SHA `46cc04ac899bc4e7c610b6ce9ec4796fb553ba1766fc7b6462fa7faa3aeec0c4`.

Independent reference is built by `generalizationJsonOracle.py` and `freezeGeneralizationOracle.py` using an original-byte JSON token walker and separately cross-checked Python standard JSON semantics. It checks exact native JSON Pointer path, type, value and half-open UTF-8 **original source byte** positions. The pinned private oracle SHA-256 is `1918c4da2e4c6b5dd5dd6381e976cc31fd82d337da4a25f32ce7f3eecbed2881`. All raw original events, expected values, original source identity and independent oracle are private mode **0600** in a mode **0700** directory, never in Git or CI.

| Frozen split | All original events | Independently JSON-scorable events | Scorable source leaf fields | UNSCORABLE excluded |
| --- | ---: | ---: | ---: | ---: |
| Development: converter JSON, endpoint JSON and other physical originals | 213 | 40 | 1,302 | 173 |
| Sealed: Suricata original JSON and independent log-zoo nonJSON | 552 | 548 | 14,353 | 4 |
| **Combined** | **765** | **588** | **15,655** | **177** |

The prior private source oracle was frozen *before* candidate scoring and used to freeze the development-vs-sealed family split. The candidate source SHA was separately frozen in private `candidate-frozen.json` **before opening the sealed scored results**. No cherry-picked or synthetic-only positives are included in the sealed denominator. JSON source syntax does not certify manufacturer decoding, upstream packet identity, normalized field mapping or target native execution.

## Reusable correction, not vendor regexes

New `src/poc/boundedStructuralSourceSpans.ts` is a separate bounded structure layer, **not** part of the shipping parser:

1. Preserve original raw string and total UTF-8 bytes. Locate standalone JSON or a validated Syslog-envelope JSON body (RFC3164/RFC5424); do not invent envelope fields or timestamps.
2. Walk nested JSON objects and arrays with bounded recursion, node count, field count and maximum 64 KiB record length; retain source native JSON Pointer leaf paths.
3. Represent each scalar as a native JSON type, exact value and original half-open byte range; replay each source byte slice separately to assert exact values.
4. Reject collisions, repeated decoded keys, dangerous object keys, unpaired Unicode surrogates, invalid/truncated JSON boundaries, unsafe JSON integers and numeric overflows before exposing any candidate fields.
5. Never auto-promote source syntax: exact source-span candidates remain `REVIEW_ONLY`; unsafe cases become `ABSTAIN_UNSAFE`; unknown formats are `RAW_ONLY`. No implicit vendor semantics or native success.

This closes a **structural evidence gap** for multi-line nested JSON and source spans; it is not a new fully qualified vendor parser. The existing bounded Multi-Pass + Generic Structural/Funnel architecture is retained untouched.

## Same-denominator comparison

The unchanged product-style baseline was evaluated via `parseSecurityInput`, with correct result projection: single-event direct JSON fields, and `Records` wrapper reconstruction from supported `json_batch`. The earlier development projection experiment used an incorrect field tree, and was corrected **before** the sealed evaluation; the authoritative baseline file is private `baseline-v3-*.json`. There are no product code changes.

| Exact original evidence | Development baseline | Development new candidate | Sealed baseline | Sealed new candidate |
| --- | ---: | ---: | ---: | ---: |
| Scorable events | 40 | 40 | 548 | 548 |
| Original JSON leaf fields | 1,302 | 1,302 | 14,353 | 14,353 |
| Field name, typed-value TP | 1,302 | 1,302 | 14,353 | 14,353 |
| Field FP / FN | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| Original field **name + type + value + byte-span** TP | N/A (span not exposed) | **1,302** | N/A (span not exposed) | **14,353** |
| Candidate span FP / FN | N/A | **0 / 0** | N/A | **0 / 0** |
| Exact source event | 40 | 40 | 548 | 548 |
| Scorable candidate abstentions | N/A | 0 | N/A | 0 |
| Excluded UNSCORABLE events | 173 | 173 | 4 | 4 |
| Incorrect auto-promotion | No candidate exposure | 0 | No candidate exposure | 0 |

**Qualified Funnel comparator:** The unchanged `inspectGrammarFunnel` inspection was also recorded on these same originals. Its separate KV/CSV lexical suggestion path reported `RAW_ONLY` for all 548 sealed pretty-printed JSON originals (multi-line source), while the unchanged `parseSecurityInput` baseline did successfully extract 548/548 events. Therefore `RAW_ONLY` here describes only the optional lexical suggestion path; it is **not** a product parse failure. The isolated candidate adds original JSON byte spans to the broader structural path without replacing or weakening the qualified Funnel.

**Interpretation:** Existing baseline already achieves 100% name/type/value extraction on these source JSON cohorts. The new verified capability is independent original-byte span reconstruction on nested/multi-line JSON **without losing the existing exact name/value accuracy**. Do not report a 0-to-100% gain in shipping parser success; the baseline does not expose spans for this comparator, not documented wrong spans.

## Safety / adversarial controls

- New deterministic Vitest suite: original UTF-8 multibyte, emoji, double-quote escapes, nested arrays, RFC3164/RFC5424 prefixed JSON, duplicate keys including Unicode escape aliases, unsafe precision and malformed/oversized/deep structures. RED (3 test failures due to scanner sticky numeric boundary) then GREEN (9/9).
- Independent Python negative-unit oracle: **8/8** PASS.
- Affected SHA-pinned historical guard only, **1,361 previous original + 2,892 malformed mutations**, including 900 Sophos mutated events; **0** new malformed `REVIEW_ONLY` matches, **0** auto-promotions, **0** byte-accounting errors. This replays the **new stage only**, not earlier #29–#43 accuracy experiments.
- The new stage observed **91/1,361** previously pinned non-mutation originals as syntax-only `REVIEW_ONLY`, but none is newly field-certified in this affected replay; **0/2,892** invalid mutations became `REVIEW_ONLY`. These additional 91 observations are not independent TP or event-accuracy evidence, and all are non-promotable.
- New development-only metamorphic mutation experiment: 40 independently JSON-verified events × 4 modifications = **160 synthetic controls**. Duplicate keys, Unicode-decoded alias collisions, greater-than-JavaScript-safe integer and truncation were all `ABSTAIN_UNSAFE` (40 each) with zero candidate success. The unchanged baseline returned structural `ok:true` on all 40 duplicate-key and all 40 unsafe-integer modified examples. **These are deliberately mutated developer-origin events, not authentic new vendor observations or independent field-accuracy denominators.**

Original matching, raw retention and structural acceptance are distinct from manufacturer field-semantic and native/Stellar validation. Unknown escapes and non-JSON body formats were not decoded or promoted.

## Reproduction and explicit qualification

```bash
python3 scripts/poc/pinGeneralizationSources.py
python3 scripts/poc/freezeGeneralizationOracle.py
python3 -m unittest discover -s scripts/poc -p testGeneralizationJsonOracle.py -v
node_modules/.bin/vitest run src/poc/boundedStructuralSourceSpans.test.ts
node_modules/.bin/vite-node scripts/poc/runBlindGeneralizationEvaluation.ts development
node_modules/.bin/vite-node scripts/poc/runBoundedStructuralBlindCandidate.ts development
node_modules/.bin/vite-node scripts/poc/runBoundedStructuralSafetyReplay.ts
node_modules/.bin/vite-node scripts/poc/runGeneralizationMetamorphicSafety.ts
# Before the sealed score, only after candidate source is final:
python3 scripts/poc/freezeGeneralizationCandidate.py
node_modules/.bin/vite-node scripts/poc/runBlindGeneralizationEvaluation.ts sealed_holdout
node_modules/.bin/vite-node scripts/poc/runBoundedStructuralBlindCandidate.ts sealed_holdout
npm run typecheck && npm run build && npm test
```

Frozen private files are immutable; a scorer rejects identity drift or conflicting output observations. A future material candidate change must receive a new separate seal and **new** holdout; it cannot silently rescore the same sealed set as fresh evidence. Exact-head GitHub CI/browser/loopback evidence must be separately confirmed before claiming a fully green draft.

## Boundary and follow-on without integration authorization

- **Qualified narrow finding:** new isolated source-byte-traceable, bounded nested JSON source extraction without field/value regression on an independently sourced sealed cohort; synthetic structural loss/duplicate controls fail closed.
- **Not qualified:** generalized improvement to all unknown security formats, unknown manufacturer escape semantics, non-JSON independent field extraction, native Stellar/Fluentd behavior, product release or automatic confidence thresholds.
- The most valuable next independent study is a truly independent **non-JSON** KV/CSV/CEF/LEEF byte-field oracle across distinct devices/transports. If unavailable, retain UNSCORABLE and research reusable envelope/body adjudication in isolation, never invent expected values.
- R1 Juniper residual 5, Defender compiler, Umbrella quoted 23-column CSV; R2 beginner progress; R3 owner visual mapping review and mobile; R4 exact-head E2E/owner approval are **carry-forward backlog only**, not authorized work in this PoC.
