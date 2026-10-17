# Independent non-JSON original-source field accuracy and CEF transfer (2026-10-17)

## Decision, isolation, and source scope

This is an evidence-only, **isolated source extraction PoC** stacked on Draft PR #46, exact parent `ceb048f92b905a70b874ac40650ba54f7ede512b`. The separate product stays at `da94aa9177c6b652eee47768efb98a9d47df8c5e`. None of the product parser, qualified Multi-Pass / Generic Structural / accuracy-first Funnel, main, native Fluentd/Stellar engine, DP, sensors, releases, deployment or existing Draft PRs #29-#46 have been modified.

The purpose is to make previously unseen **publisher-authored non-JSON source field/lexical-value/UTF-8 byte-offset triples** more precise while resisting invented certainty. This is **not** a claim of native parser execution, vendor semantics, complete field coverage or shipping parser accuracy.

### Integrity timeline: source and truth frozen before first candidate score

1. Upstream sources pinned unchanged by repository revision, file path, SHA-256, byte length and Apache-2.0 license. Public metadata: `scripts/poc/independentNonJsonSources.pinned.json`. Twenty source files, 77,298 bytes, source manifest SHA-256 `1998fd42a079cd87f059acc1052d1da57b4beee809f9dc11b7a1ebf18a3d7d1d`.
2. Third-party NiFi/Fluent Bit assertions and unmodified fixture bytes independently transformed into field+value+original-UTF8-span oracle by Python before running any parser. A **pre-scoring** v1 qualification correction avoids treating every row of an upstream-invalid whole file as an individually invalid record. Both immutable v1 and v2 remain private; **v2** `18c25739376c4bd7289066e147ac73fc5e55344385b0312e7c0e6cab00cea17b` is the sole evaluation denominator. Public counts: `scripts/poc/independentNonJsonOracle.v2.pinned.json`.
3. **Separately pinned before transfer evaluation**: Apache Metron and Logstash original Apache-2.0 test sources, twelve files / 131,796 bytes, manifest SHA-256 `310a97c50cddb49ce914dbfe43baa321d4ee512c8e62cdd53f176c650b2e8fe3`. Publisher-authored Metron Java expectations and independent CyberArk JSON/original-string identity became transfer goldens SHA-256 `6944e92d0e5f0f8c4db9fe96a7d05ea0a07a68cb111db2e9bb17c97ddfb2a07b` **before** candidate scoring.
4. All source bytes, original logs and golden source field/value lists remain outside Git in `~/.local/state/parserstudio-independent-*` (0700 directories, 0600 originals/oracles). Git contains only public provenance, SHA/count summaries, independent extraction scripts and PoC code. CI does not need or upload private raw oracle material.

No previous Influx, OpenTelemetry, Jeromer, Elastic, PR #29-#46 original or malformed corpus appears in the new accuracy numerator. These earlier corpora are *only* replayed as regression guards.

## Independently frozen denominators

| Partition | Scorable originals | Publisher-supported field/value/source-span triples | Explicitly excluded / controls |
| --- | ---: | ---: | --- |
| NiFi CEF + NiFi/Fluent Bit Syslog | **16** (8 CEF, 8 Syslog) | **145** (114 CEF, 31 Syslog) | 9 duplicate original messages, 3 UNSCORABLE, 2 upstream-invalid controls |
| Separate Metron CEF transfer | **3** | **19** | 5 UNSCORABLE, 1 upstream-asserted negative control |
| **Total independent source score** | **19** | **164** | **All exclusions preserved** |

Some original CEF extension semantics require external profile information. The independently asserted subset is source lexical truth (published header values, explicit getter assertions, original fixture value bytes), **not** a complete semantic parse of all fields. Columns without independent expected name/value and byte range are excluded from TP/FN; *extra candidate fields outside the asserted reference* are tracked as `unscoredExtraClaims`, **not silently accepted as TP nor spuriously asserted FP**. No source field is added to a denominator because the candidate emitted it.

The CSV settings-only fixture had no independently authored record field values and remains UNSCORABLE. Logstash encoder-output regex examples are not equivalent to independently scored input parse records. LEEF, escaped-wire firmware semantics, native runtime and non-CEF multiline CSV remain unqualified; no percentages for those formats are claimed.

## Same-denominator results: new NiFi/Fluent Bit cohort

| Metric | Unchanged product | Qualified Generic Structural | PR #46 source arbiter | New isolated CEF source observer |
| --- | ---: | ---: | ---: | ---: |
| Independently supported field+value matches /145 | 54 | 54 | 16 | **90** |
| Exact source name+value+UTF-8 span TP /145 | Not emitted | Not emitted | 16 | **90** |
| Source triple FP / FN | Not measurable | Not measurable | **2 / 129** | **2 / 55** |
| Exact-on-all-asserted-field events /16 | Source spans unavailable | Source spans unavailable | 1 | **4** |
| CEF source triples (TP / FP / FN) | Source spans unavailable | Source spans unavailable | 0 / 0 / 114 | **74 / 0 / 40** |
| Syslog source triples (TP / FP / FN) | Source spans unavailable | Source spans unavailable | 16 / 2 / 15 | **16 / 2 / 15** |
| Explicit upstream-invalid controls wrongly given lexical REVIEW | - | - | **0 / 2** | **0 / 2** |
| Source/native automatic success promotions | Not evaluated as source proof | Not evaluated as source proof | 0 | **0** |

A product field+value match is **not** a verified byte span, and its number must never be compared as a native or complete source-parser success rate against the isolated observers. Both qualified and new stages retain exactly the same Syslog result, including **two pre-existing source claim disagreements/FP and 15 FN**; none is concealed or promoted. The measurable fresh source-accuracy lift on this fixed denominator is **+74 exact triples, -74 FN, unchanged 2 FP**; it is entirely in the new CEF grammar.

## Cross-publisher transfer after freezing the second golden

| Original Metron CEF publisher case | Independent expected triples | PR #46 exact | New exact |
| --- | ---: | ---: | ---: |
| Explicit basic header + extension assertions | 10 | 0 | **10** |
| Escaped-header/value assertion | 2 | 0 | **0** (conservative ABSTAIN) |
| CyberArk independently authored original-string JSON reference | 7 | 0 | **7** |
| **Total transfer** | **19** | **0** | **17** |

Both stages preserve the explicitly invalid Metron non-CEF control (0 incorrect review, raw retained). The transfer is only **3 qualified originals** from a *different upstream project*, not a large vendor-wire conformance study. A normalized semantic field in Metron JSON is used only to corroborate explicitly source-replayable CEF header originals. The complex escaped/unquoted extension with uncertain semantics is **not decoded by guess**; its two false negatives remain in the fixed reference.

Taken together across these two separately pinned partitions: isolated baseline **16 TP / 2 FP / 148 FN** against **164** source triples, new observer **107 TP / 2 FP / 57 FN**, **+91 exact source triples** and **no additional observed FP**. These are totals of **partial independently asserted goldens**, not 107/164 complete events or a general security-log parsing rate.

## Reusable structural correction and safety

`src/poc/independentNonJsonStructural.ts` composes the unchanged PR #46 stage with a bounded standard **CEF 7-field header + lexically constrained extension** detector. It recognizes standalone CEF or a bounded timestamp/hostname-prefixed form without asserting an unqualified transport envelope to be RFC3164. There are no manufacturer-specific escape fixes, normalization substitutions, speculative unescaping, auto-generated field names or wild-card parse promotions. The source span for every claimed leaf is checked against the original UTF-8 bytes. Unknown header escaping, partial headers, unsafe Unicode, oversized input, and uncertain CEF extension quoting remain ABSTAIN or header-only review with explicit `NOT_PROVEN`.

All outputs remain review/abstain/raw and `autoPromoted=false`, `independentOracleCertified=false`, `nativeVerified=false`. Negative independent source/provenance/profile VETO from the underlying PR #46 is inherited and cannot be overwritten by a claimed ACCEPT/EXACT; any VETO produces `ABSTAIN_UNSAFE`. The total branch count is always at most eight.

A dedicated **historical safety-only replay**, using old SHA-pinned sources *without counting them as new accuracy*, tested **1,361 earlier originals and 2,892 invalid mutations**. Versus unchanged PR #46: **zero newly reviewable original/invalid messages, zero new CEF claims, zero byte/UTF-8 span drift, zero auto success promotion, zero branch overruns, zero veto bypass**. The old **197 / 2,892 invalid** syntax-only REVIEW proposals are **still there**, neither removed nor independently approved. Source/body completeness remains unresolved on those historical negatives.

## Reproduction (private oracle must already be available)

```bash
python3 scripts/poc/pinIndependentNonJsonSources.py
python3 scripts/poc/freezeIndependentNonJsonOracle.py
python3 scripts/poc/qualifyIndependentNonJsonOracle.py
python3 scripts/poc/pinIndependentTransferSources.py
python3 scripts/poc/freezeIndependentTransferOracle.py
node_modules/.bin/vite-node scripts/poc/scoreIndependentNonJsonHoldout.ts
node_modules/.bin/vite-node scripts/poc/scoreIndependentTransfer.ts
node_modules/.bin/vite-node scripts/poc/runIndependentNonJsonSafetyReplay.ts
node_modules/.bin/vitest run src/poc/independentNonJsonStructural.test.ts src/poc/boundedSourceBodyArbiter.test.ts src/language-policy.test.ts
npm run typecheck
npm test
npm run build
```

The two independent score scripts fail closed on frozen SHA/denominator drift. These Python upstream-source/oracle steps are **private evidence reproduction**, not part of public CI. Public CI must run full deterministic TypeScript tests, build, Chromium browser acceptance and actual localhost backend HTTP integration on the **same pushed head** before any PR is described as CI-validated.

## Open limitations and handoff

1. **No general source-complete certification** for CEF escaped/quoted extensions, multiline/unlabeled CSV, LEEF, mixed RFC-enveloped CEF, supplier-specific actual wire escape profiles or fully arbitrary nonJSON logs. A surviving REVIEW_ONLY token never means producer verified or a native parser passed.
2. **Current frozen coverage is small and imbalanced**: 19 scored original events across CEF and Syslog, not large-scale unseen vendors. Subsequent accuracy work requires an independently authored third-party original+expected *LEEF/CSV/quoted KV and RFC-enveloped CEF* cohort, with original source revision and golden SHA sealed before any candidate evaluation. Keep UNSCORABLE if truth is unavailable.
3. The **pre-existing two Syslog source disagreements, 197 invalid review-only lexemes and unqualified native semantics** remain visible. No manufacturer-specific patching or result cherry-picking.
4. Product R1 (Juniper 5/100, Defender compiler, Umbrella quoted CSV), R2 (beginner visible progress), R3 (owner Review Fields → Map Fields → Create Parser visual acceptance), and R4 (freeze exact product head / Chromium / Full User E2E / owner gate) are **handoff-only**, never an authorization for product integration, main change, release or merge.
