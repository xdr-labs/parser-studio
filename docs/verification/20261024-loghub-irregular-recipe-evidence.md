# 2026-10-24 — Loghub irregular-source accuracy and reviewed ParserRecipe trial

## Decision and evidence classes

The existing Multi-Pass engine remains the primary parser. This change is a **bounded structural recovery and review-prompt improvement**, not a replacement engine, vendor/firmware classifier, external AI integration, or Stellar Cyber target certification.

Tests use the public [Loghub benchmark](https://github.com/logpai/loghub) pinned to upstream commit `dd61d0952749ee7963bde24220d1be5ede023033`. **Twelve source families × 2,000 actual published physical log lines = 24,000 lines**, retrieved from the pinned raw GitHub commit with source file SHA-256 and unchanged private files. Families: OpenSSH, Linux, Apache, HDFS, OpenStack, Hadoop, ZooKeeper, Proxifier, BGL, Mac, Android, Spark. Public Loghub samples are not independently authenticated physical-vendor firmware captures. They do not provide independently verified per-field security semantics. This work neither includes the original copyrighted dataset files in Git nor automatically sends them to any AI service.

### Original-source benchmark, identical 24,000 lines

The reproducible `tools/benchmark_loghub_irregular_20261024.py` runs the **offline Python Multi-Pass source extraction**, not complete end-user parser generation, once per physical line and audits preservation of every original UTF-8 byte. `tools/compare_loghub_source_benchmark_20261024.py` requires identical original Git commit/file SHA, 24,000 input lines, no accounting exceptions, no regression in nine untouched source families, and correct source-only status interpretation. Private immutable baseline and candidate ledgers are not committed.

| Evidence | Before main | After candidate |
| --- | ---: | ---: |
| Physical lines processed | 24,000 | 24,000 |
| SOURCE_PARSED (source grammar, not verified semantics) | 4,511 | 4,511 |
| PARTIAL (review required) | 13,747 | 17,573 |
| RAW_ONLY (no safe source extraction) | 5,742 | 1,916 |
| Original UTF-8 byte-accounting failures | 0 | 0 |
| Source field value spans | 100,331 | 130,531 |
| Source residual bytes | 1,906,141 | 1,302,255 |

**3,826 previously RAW_ONLY logs now expose verifiable fields while remaining PARTIAL**, not false FULL success. Existing SOURCE_PARSED count is deliberately unchanged. The earlier experimental intermediate showed 7,996 SOURCE_PARSED, but failed the semantic honesty requirement and was superseded by this conservative final candidate. The exact decision is structural **header recognition, not arbitrary message meaning inference**. Total candidate residual byte reduction is 603,886. Every one of the 24,000 cases still has potential grammar or semantic review needs under this stricter benchmark.

### Root improvements and safety

1. Exact validated yearless **Android Logcat threadtime** and **bracketed month.day application/target** layouts return only producer-delimited fields, preserving free-text message without guessing action, attacker, user, year, or timezone. Keep `FREE_TEXT_FIELD_ROLES_NEED_REVIEW`. A bracketed month/day line cannot be mistaken for a JSON array, so framing stays exact. Do not replace an existing qualified source parser.
2. A generic **six-digit datecode / timecode / process / severity / component** header retains the original unmodified message and byte offsets for HDFS. Additional Apache/Java patterns are conservative helper-only candidates, never promoted over a preexisting partial grammar with real value spans.
3. Value-free ChatGPT prompt hints (fixed shape identifiers, accepted record counts, explicitly unverified potential field names) help a model propose a bounded **REVIEW_ONLY** named-regex recipe while reminding it to use only source-supported values, avoid literal hardcoded IP/hostnames, and require source-disjoint holdouts.
4. All unsupported, invalid-date, overlong, control-character, mixed and malformed records remain fail-closed. No model-suggested recipe applies automatically.

Actual `preview_batch` API-function contracts were exercised on **4,000 Proxifier and Android physical records in bounded batches**, with 4,000/4,000 original event boundaries and source SHA-256 matching; **19,875 independently checked publisher-format field source values and byte positions, zero mismatches**. This is structural/lexical evidence, not semantic accuracy across the full 24k.

### GPT-6 recipe trial: real application, NOT a separate independent model invocation

Using this same ChatGPT conversation, GPT-6 authored **two new ParserRecipe v0.2 bounded named-capture regex proposals** (Proxifier and HDFS) from a short pinned public Loghub sample. They are **not** externally/independently invoked provider responses, cannot be counted as an external model accuracy pass, and are explicitly labelled as a same-conversation model trial.

Each proposal followed **actual deployed public Chromium**, no mock of the parser backend: five training records → genuine manually copied prompt + exact project/source metadata → response pasted in `Check ChatGPT Result` → **10 source-disjoint holdout records** → `Test Proposed Fix` PASS → explicit QA approval → actual backend validated Ruby/CONF DRAFT download. Both passed full UI paths.

The two generated independent native Ruby parser fragments were subsequently executed against the **full 2,000 actual Loghub physical-line sources each (4,000 total events)** in the isolated local Ruby 3.2.3 runtime. Each event produced one record, **zero native callback parser errors**. A separate lexical split-based capture oracle compared **24,000/24,000 source field value occurrences**, exact. This measures **lexical named-capture fidelity** only, not correct security semantics, Native Fluentd plugin loader, independent LLM output or target import. No native/DP/sensor/production action was performed.

Reproducible private evidence and SHA:

- Corpus manifests: `/home/aella/.local/state/parserstudio-irregular-20261024/corpus/UPSTREAM.json`.
- Baseline/candidate: `pre-change-multipass.json`, `candidate-multipass.json`; verified `delta-evidence.json`.
- True bounded API function source-span checks: `api-qualified.json`.
- Same-chat authored v0.2 trials: `same-chat-model-recipe.json`; actual source-specific Ruby/CONF pairs retained privately, no raw in Git.
- Independent lexical oracle over 4,000 native Ruby events: `native-recipe-4000-benchmark.json`, SHA-256 `fdce439367d2ff951a5463c6a9a35cb77394d06608fbb0f86c2bb2f0f4c13c9a`.

### Additional manual ChatGPT-assisted recovery cross-check

A second **same-session** assistant-authored v0.2 browser trial used two Proxifier and two Android source records from the pinned corpus (not the same as an independent external provider inference), followed by different two-record holdouts. Both strict v0.2 proposals were **accepted for testing, passed source-disjoint holdout, required explicit approval, and downloaded actual Ruby/CONF DRAFT pairs** through the deployed public HTTPS UI. The original 2k rows per family matched the reviewed regex grammar, and isolated Ruby 3.2.3 callback execution on three separate source records per family returned the expected mapped fields without errors. This is supplementary to the separate **Proxifier + HDFS** 4,000 native-record evidence above; overlapping Proxifier records are **not** double-counted as unique source events.

A further independent *lexical source* oracle replayed the downloaded Android DRAFT Ruby on **2,000 different Android log records**, observing **2,000/2,000 native callbacks, 10,000/10,000 selected source field values, zero parser errors**. This shares the original 2,000-line Android corpus already used in the structure benchmark; it is additional evaluation depth, **not 2,000 new unique logs**. Private reproducible result: `inchat-native-android-2000-evidence.json`. The earlier Proxifier+HDFS native 4k benchmark remains separately reproducible and is not combined into a misleading independent-model accuracy denominator.

New focused `src/guided/sameChatRecipePolicy20261024.test.ts` checks both bounded named-capture regex shapes against strict ParserRecipe v0.2 schema and refuses representative invalid month/clock/unframed inputs. A second, more restrictive date/time capture specification matched 2,000/2,000 original lines per Proxifier and Android corpus but is **not yet a newly accepted production recipe**. All these authored proposals remain **SAME_CHAT_ASSISTANT**, with **zero** separate external ChatGPT inference runs.

### Evidence gates and next work

- **Separate independent external ChatGPT provider/model calls: 0** (no authorized separate provider API, connected model tool or credentials). A true independent model benchmark requires model ID/run ID, response SHA, multiple distinct prompt/response runs, strict recipe acceptance, holdout correctness and hallucination scoring. Do not conflate this same-conversation GPT-6 trial with a separately called provider.
- **Authenticated physical-device original logs: 0**; the published Loghub corpus does not supply model-external vendor ground truth. Do not compute global semantic field precision/recall from SOURCE_PARSED counts.
- **Actual Stellar Cyber 7.0 install/reception: excluded by the owner.** No targetVerified claims.
- Keep all source modifications on a focused Draft PR with exact-head CI. No implicit merge or development Web deployment from this research candidate.
