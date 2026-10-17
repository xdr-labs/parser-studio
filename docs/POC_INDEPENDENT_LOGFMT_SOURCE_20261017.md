# Independent logfmt / quoted KV source-byte fidelity (2026-10-17)

## Scope, precedence and non-production boundary

This **isolated evidence-only PoC** stacks exclusively on Draft PR #49 exact HEAD `0754f261744ff237d4b1a0b0de15caf2ccd4121b`; #49 is stacked on earlier Draft PRs #48 → #47 → #46. It introduces only `src/poc`, `scripts/poc` and a PoC report. All product parser behavior, Multi-Pass + Generic Structural/Funnel, UI, native Fluentd/Stellar export, main, DP, sensor, deployment, credentials, release and PR merging remain strictly out of scope. Separate product HEAD `da94aa9177c6b652eee47768efb98a9d47df8c5e` is preserved.

The owner's goal is **fundamental field-name/value/source UTF-8 byte accuracy improvement**, not arbitrary perfectly parsed logs or vendor-specific one-off escape fixes. A transport envelope, a lexical KV candidate and independently attested original field truth are separate layers; lexical evidence **never automatically certifies** producer or native parser correctness.

## New source/oracle provenance sealed BEFORE candidate comparison

The original upstream MIT-licensed decoder test sources were selected, downloaded and SHA-pinned before deriving expected fields or inspecting proposed TypeScript observer output.

| Original third-party publisher | Immutable revision | Upstream assertion used |
| --- | --- | --- |
| `go-logfmt/logfmt` | `804e98fff868b206344991c57a8182172e5ba41e` | Go `TestDecoder_scan` author's original `data` input plus `want [][]kv`, independently compared with `reflect.DeepEqual` |
| `kr/logfmt` | `19f9bcb100e6bcb308b5db29c682de01e9b3f2e6` | Go `TestDecodeCustom` author's separate input and `want []pair` + `reflect.DeepEqual` |

**Two original test files / 8,847 bytes**; source manifest SHA-256 `ca5024b95a7fdfa1f0633c8d6e26ff9004eefb91f2ad62f8efc0cc8ebcee6fdb`. Public immutable source metadata: `scripts/poc/independentLogfmtSources.pinned.json`. Reproduction: `scripts/poc/pinIndependentLogfmtSources.py`.

An **independent Python lexical byte oracle** reads only the original authored Go input/expected literals, checks expected keys/values against the original byte slices, and seals original UTF-8 start/end offsets before the TypeScript candidate is scored. Reference SHA-256 `1dc71e3d28513c9f8a46f918c2d8b938406942a18a45e4faca203908283ec4d8`. Public metadata: `scripts/poc/independentLogfmtOracle.v1.pinned.json`; reproducible via `scripts/poc/freezeIndependentLogfmtOracle.py`.

The original publisher Go test source files, original event messages, expected original names/values and independent golden source positions reside **only in the private** `~/.local/state/parserstudio-independent-logfmt-20261017/` directory (0700 directory, 0600 files), **not committed or uploaded**. CI does not require private original/golden data. Only public source revision, license, SHA/count metadata, reproduction scripts and separate synthetic unit tests are retained in Git.

### Immutable eligibility and denominator

- Publisher-authored test table: **16 selected cases**, of which **10** independently original, scorable partial logfmt records contain **23 publisher-asserted named field/value/original UTF-8 byte-span triples**.
- Scorable by publisher: `go-logfmt/logfmt` **9 original cases / 17 triples**, `kr/logfmt` **1 original case / 6 triples**.
- Excluded rather than labeled success: **3** standalone originals with no independently asserted source value literal (bare/nil), **2** samples with no independently scored triple, **1** dynamic/generated source input. **Seven null/bare expected source slots** are not invented as nonempty values. Their prior unsupported status is retained.
- **Six** scorable originals are publisher single-record input tests; **four** original source inputs contain publisher-authored multiple record boundaries. A separately qualified record-frame context is required for interpreting the batch; no unknown Syslog stream is automatically divided into logfmt records.
- Repeated source key names are matched **bijectively by name, value and exact source byte position**, not counted as FP just because more than one correct original occurrence shares a name. All external expectations stay immutable.
- Producer library differences over an **unquoted empty assignment** are unresolved: `go-logfmt/logfmt` demonstrates nil-value handling while `kr/logfmt` asserts empty-string values. Without independent producer/profile provenance, the generic stage declines both unquoted empty claims rather than guessing. Two empty-string expected source triples therefore remain **explicit FN** in the fixed denominator.

## Original source-name/value/byte-score comparison

| Metric on the same independently frozen 23 triples | Preceding #49 source arbiter | New isolated generic logfmt lexical observer |
| --- | ---: | ---: |
| Original source events with partial truth | 10 | 10 |
| Source name + decoded value + exact UTF-8 span TP | **0** | **21** |
| Wrong named/value/source-span claim FP within author-asserted scope | **0** | **0** |
| FN on unchanged reference | **23** | **2** |
| All independently asserted field triples exact on an original | 0/10 | **9/10** |
| Automatic parser/native/producer success promotions | 0 | **0** |
| Original byte loss, UTF-8 replay failure or branch >8 | 0 | **0** |

Separate publisher results: `go-logfmt/logfmt` **0/17 → 17/17** exact source triples, `kr/logfmt` **0/6 → 4/6**. **No 100% coverage is claimed**, even within the small library test cohort. This is **not a manufacturer/device-wire, target-native, product regression success rate**, and the sample cannot estimate confidence on arbitrary new security products. Fields outside the authored source reference are not certified TP; missing author source values remain UNSCORABLE.

## Vendor-neutral bounded correction

`src/poc/independentLogfmtSource.ts` composes with unchanged prior PR #49. It is a bounded Go-style logfmt structural evidence scanner and **does not replace `parseSecurityInput`, product UI, qualified Multi-Pass/Funnel or target export**.

1. No user-provided or independent logfmt transport/framing evidence → unchanged previous arbiter; unknown raw source receives **zero new logfmt fields**.
2. On externally established `CONFIRMED_LOGFMT_SINGLE_RECORD` / `CONFIRMED_LOGFMT_BATCH_RECORDS`, retain exact UTF-8 original source bytes and separate record indexes. Spaces/tabs and explicit boundary bytes have bounded source ownership, not vendor semantic meaning. No uncontrolled splitting of unknown multiline events.
3. Parse source key names including valid Unicode, original repeated key occurrences, bare/nil ambiguity, bounded quoted values and the *standard* lexical escape subset only. Unknown escape or malformed quote → fail closed.
4. Replay the **original quoted/unquoted value slice independently** (JSON-equivalent simple logfmt escape grammar) before emitting an exact source byte range. Preserve original lexical span alongside the decoded string; never silently normalize or invent an original key.
5. Quoted values with independently replayable empty `""` may be reviewed, but unknown **unquoted empty `x=` is left unclaimed**, as two independent publisher implementations disagree on its semantics without a source profile.
6. Adjacent quoted/key assignments permitted only when an entire following key `=` starts a bounded token; marked `REVIEW_ONLY_PARTIAL`, never success.
7. Bounds: maximum original 16 KiB, 256 named fields, 64 record boundaries, at most **8** branch attempts, original raw unchanged.
8. Dispositions `RAW_ONLY`, `ABSTAIN_UNSAFE`, `REVIEW_ONLY_LOGFMT_LEXICAL`, `REVIEW_ONLY_PARTIAL` with `autoPromoted=false`, `independentOracleCertified=false`, `nativeVerified=false`; independent source, structural profile or original truth **VETO always wins**, claimed positive verdict never certifies source/native success.

## Historical safety-only replay (never a fresh accuracy denominator)

- **1,361** older original security events + **2,892** previously invalid/adversarial mutations were replayed **only for regression safety**, with source SHA and counts unchanged.
- The previous **197 historical syntactically REVIEW_ONLY malformed sources remain REVIEW_ONLY**, not approved or silently fixed. **Zero** newly reviewable invalids, zero changed old-result classifications, zero byte/span drift, zero auto source/native success, zero branch-budget failures, zero VETO bypass and zero unframed source-claim leaks.
- All **50 separately frozen, previously scored non-logfmt original events** (CEF/Syslog/LEEF/CSV) remain byte-for-byte identical to the preceding arbiter, without reusing their source claims as new logfmt accuracy.
- Tests on synthetic malformed/UTF-8/quoted/repeated/batch records in Git are **regression**, not new independent score.

## Reproduction and CI boundary

```bash
python3 scripts/poc/pinIndependentLogfmtSources.py
python3 scripts/poc/freezeIndependentLogfmtOracle.py
node_modules/.bin/vite-node scripts/poc/scoreIndependentLogfmtBaseline.ts
node_modules/.bin/vite-node scripts/poc/scoreIndependentLogfmtCandidate.ts
node_modules/.bin/vite-node scripts/poc/runIndependentLogfmtSafetyReplay.ts
node_modules/.bin/vitest run src/poc/independentLogfmtSource.test.ts src/language-policy.test.ts
npm run typecheck
npm test
npm run build
```

**Final acceptance requires the exact pushed candidate HEAD** GitHub Actions to complete deterministic unit + typecheck/build + real Chromium user scenarios + pinned independent backend build + **real Chromium↔localhost HTTP** integration. Do not claim this PoC CI verified before those exact-HEAD checks actually finish. Native Fluentd/Stellar parser is not being run or approved.

## Explicitly remaining/unqualified scope

Real device-wire UTF-8 escaped KV records, producer-specific nil semantics, unqualified multi-record framing, unknown CEF/LEEF firmware escaping, unreviewed unlabeled security CSV column meaning, semantic normalization to Stellar fields, and actual native target runtime remain **UNSCORABLE/NOT VERIFIED** until independent original expectations and runtime evidence exist. Historical 197 bad lexical REVIEW suggestions also remain unresolved and are not counted as successful repairs. Avoid manufacturer-specific quick fixes. If further independent source truth is missing, record evidence limitation, not a spurious 100% score.

Product **R1–R4 remains HANDOFF ONLY**, including Juniper five residual/Defender compiler/Umbrella quoted CSV, beginner progress UX, owner visual mapping acceptance/mobile and exact product HEAD full user E2E/owner gate. This PoC does not authorize product integration, main change, DP/sensor, native qualification, deployment, merge or release.
