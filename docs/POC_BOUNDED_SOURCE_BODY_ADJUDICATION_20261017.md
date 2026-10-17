# Bounded generic source/body adjudication and external conformance (2026-10-17)

## Owner goal and scope

The goal is durable improvement in *source extraction correctness*, not an endless series of vendor-specific fixes or universal 100% parsing. This document describes **an isolated PoC** stacked on Draft PR #45, exact base HEAD `7b05891ab30406b241d046d179fb48f11001db9b`. No existing qualified Multi-Pass + Generic Structural/Funnel implementation or product code is replaced, and no main, DP, sensors, deployment, credentials, native target, release, or PR merge is authorized. **Every PoC status remains evidence-only**, never `SOURCE_PARSED` or target-runtime success.

The remaining general algorithm gap was that an independently replayable Syslog envelope was often mistaken for a sufficiently parsed event. A source-level body suggestion can also be a grammar false positive, especially on malformed source/device records. The new layer separates transport/envelope ownership from body syntax and preserves all original bytes and abstentions.

## Newly pinned third-party original conformance

Source selection was pinned **before any comparison to existing Parser Studio parser output**. The independent original `jeromer/syslogparser` (BSD-3-Clause) upstream source files:

- `rfc3164/rfc3164_test.go` at Git commit `bbb7299539a11043ebef9383dcfba285d583d89c`
- `rfc5424/rfc5424_test.go` at the same pinned commit

The original two-file payload contains **43,419 bytes** and two distinct SHA-256 files. The canonical public source-provenance manifest is `scripts/poc/externalSyslogSources.pinned.json` with SHA-256 `f80d0d998f78e95fd6bf5db7af2eb0980f0c0bb286e2df04a16b07562121106a`.

The independent Python oracle reads only upstream Go literal input and explicitly expected fields (including cross-check of Go `time.Date` against RFC5424 timestamp). It extracts exact original byte ranges using a separate Python lexical scanner, not the TypeScript candidate. A preliminary v1 oracle excluded Go `time.Date` expected timestamp fields, so it was corrected **before the baseline and new source-candidate comparison**. The v1 private evidence remains archived; the corrected **v2** reference SHA-256 is `15197c5b9c029831a4f6e610b0327b2716de3a46d38447948654a5cd82d639f8`, published as counts in `scripts/poc/externalSyslogOracle.v2.pinned.json`. The original Go files, field values, and byte-exact expected reference remain in a private 0700 directory as mode-0600 files. No original log strings, source expected field names/values or credentials are committed.

| Separate third-party source | Source events | Independently comparable fields | Exclusions |
| --- | ---: | ---: | ---: |
| RFC3164 upstream `TestParserValid` | 1 | 7 | 0 |
| RFC5424 upstream `TestParser` table | 4 | 31 | 0 |
| **Total** | **5** | **38** | **0** |

This is a **small independently authored library test cohort**, not an authenticated device-wire corpus. It is neither large enough for broad unseen-vendor generalization rates nor manufacturer/native/Stellar parser qualification.

### Same-denominator comparison, explicit negative finding

| Source field/value/byte KPI | Unmodified product-style baseline | Previously qualified PR #45 Syslog candidate | New layered arbiter |
| --- | ---: | ---: | ---: |
| Scorable original events | 5 | 5 | 5 |
| Original source name/value exact events | 4/5 | 4/5 | 4/5 |
| Name/value TP / FP / FN | **31 / 0 / 7** | **31 / 0 / 7** | **31 / 0 / 7** |
| Exact original source byte-offset triples | Baseline does not expose spans | 31/38, 0 byte mismatches on accepted fields | 31/38, 0 byte mismatches on accepted fields |
| Raw identity preservation | 5/5 | 5/5 | 5/5 |
| Conservative source abstention | N/A | 1/5 | 1/5 |
| Automatic native/source promotion | N/A | 0 | 0 |

The accepted case disagreement is an upstream parser-specific permissive Structured Data grammar where a named assignment contains additional whitespace around `=`. The isolated strict RFC5424 candidate abstains instead of relaxing the source grammar without independent standard evidence. Those seven expected source triples remain **FN on the same fixed denominator** because the candidate abstains; they are not removed from the reference or counted as successes. It is recorded as a disagreement and abstention, NOT a successful repaired parse or evidence of a generalized improvement. **The new layered arbiter does not improve the prior PR #45 standalone Syslog field/value score on this third-party cohort.**

Because this original source was inspected while designing the new composition layer, its composition score is a **post-hoc source-holdout replay**, not a new blind holdout for the new arbiter. No scoring of candidate performance is used to retrospectively rewrite the frozen third-party expectation.

## New reusable algorithm

New pure `src/poc/boundedSourceBodyArbiter.ts` composes existing isolated qualified primitives. It does not touch `parseSecurityInput`, `extractGenericStructural`, product UI, native export or vendor decoding.

1. Record original event raw text/length. Resolve an RFC3164/RFC5424 envelope first using byte-exact source field claims, otherwise try original standalone body. Unsafe/malformed envelope claims fail closed.
2. Recover the exact source boundary of the Syslog `message` without rewrapping, synthetic timestamps, new tags or lossy Unicode transformations. Allow RFC5424 JSON MSG containing a single-event newline only after the envelope grammar validates its framing.
3. Run a bounded **maximum eight branches**: one envelope layer, one JSON object layer, five independent KV delimiters, one conservative prefixed KV alternative. Do not recurse indefinitely. This is structural syntax; CEF/LEEF/unlabeled CSV and unknown escape semantics remain unsupported/unscorable in this PoC.
4. Replay original byte spans and decoded source literals for each named leaf/value. Preserve repeated original KV keys in order as distinct `#occurrence` claims. Do not replace existing known field values.
5. If eligible body grammars disagree on path/name/value/original byte positions, leave body ambiguous with no selected fields. Never union incompatible candidates and never pick the largest field count blindly.
6. Retain typed JSON fields and native JSON Pointer paths; represent KV values as separately checked lexical decoded values together with raw value spans. Header fields are parent-envelope ownership claims; decoded body claims may be nested within the original full-message span without destructive overlap.
7. Return only `REVIEW_ONLY_STRUCTURED_BODY`, `REVIEW_ONLY_ENVELOPE`, `REVIEW_ONLY_UNFRAMED`, `REVIEW_ONLY_AMBIGUOUS`, `ABSTAIN_UNSAFE`, or `RAW_ONLY`. `autoPromoted=false`, `independentOracleCertified=false`, `nativeVerified=false` for every result regardless of claim count.
8. An independent upstream source/grammar profile can **veto** a lexical suggestion and cause `ABSTAIN_UNSAFE`; even a claimed profile ACCEPT/source EXACT cannot promote the output to approved native/source correctness. This is a general evidence-adjudication hook, not a vendor-specific parsing rule or a caller-asserted proof of truth.

## Regression and safety evidence, never relabeled fresh blind

**Previously frozen JSON original field/value/UTF-8 oracle** (from Draft PR #44) was replayed only for regression of the new layered stage. On all **588/588 independently scorable originals / 15,655 source leaf triples**, the new unframed JSON path remains exact with **15,655 TP, 0 FP, 0 FN**, 588 exact events, no auto promotion; **177 other originals remain UNSCORABLE** by this reference. This is not new JSON accuracy research.

**Historical security negative stage-only replay**, not a re-run or re-certification of older PR #29–#43:
- **1,361 previous original events + 2,892 malformed mutations**; original bytes retained, zero span byte drift and branch-depth overrun, zero automatic source/native promotions.
- Generic source suggestions on these old originals: **217** review-only envelopes or structured candidates; **125** have lexical structured body suggestions. These are not verified original source TP without an independent body oracle.
- Previously labelled invalid mutations: **197** give lexical `REVIEW_ONLY` suggestions (including **171 Sophos** syntax-only structured-body matches and **26** other envelope-only suggestions). **They remain unapproved/unscorable, not complete parses**. No automatic success is claimed on these mutants.
- Given an **independently supplied failing profile verdict**, all **197/197** of these prior review-only malformed events downgrade to `ABSTAIN_UNSAFE`, with zero veto escapes. This is **conditional evidence-gate behavior**, not independent discovery of 197 malformed events or an autonomously reduced false-positive rate.

The conservative still-open residual is **unknown/malformed non-JSON source bodies with no qualified independent original field goldens**. Such records remain review-only or raw-only; the PoC does not claim to eliminate all false lexical candidates.

## Reproduction

```bash
python3 scripts/poc/pinExternalSyslogConformance.py
python3 scripts/poc/freezeExternalSyslogOracle.py
python3 -m unittest discover -s scripts/poc -p testExternalSyslogOracle.py -v
node_modules/.bin/vite-node scripts/poc/scoreExternalSyslogConformance.ts
node_modules/.bin/vite-node scripts/poc/scoreLayeredExternalSource.ts
node_modules/.bin/vite-node scripts/poc/runBoundedSourceBodyRegression.ts
node_modules/.bin/vitest run src/poc/boundedSourceBodyArbiter.test.ts src/language-policy.test.ts
npm run typecheck
npm test
npm run build
```

All original data/expected values and source identity remain private (0600), no customer/device/DP/sensor contacted. Full Vitest, build/typecheck and same-head GitHub Actions Chromium/localhost HTTP CI must be confirmed independently before labeling PR fully validated.

## Future independent evidence and separate product backlog

The next useful generalized accuracy lane is independently scored *nonJSON* KV/CEF/LEEF/CSV, including quoted CSV and mixed-envelope records, with authentic source byte and field goldens frozen before candidate inspection. If no legally available unmodified independent expected source truth exists, keep UNSCORABLE and work on bounded fail-closed evidence handling; do not manufacture truth or imply a native Stellar parser was exercised.

Product R1 (Juniper residual five, Defender compiler, Umbrella quoted CSV), R2 beginner progress on 100–400 logs, R3 visual Review Fields → Map Fields → Create Parser / mobile and mapping review, R4 exact-HEAD Full User E2E and owner acceptance remain **handoff only**. No authorization for product integration or release.
