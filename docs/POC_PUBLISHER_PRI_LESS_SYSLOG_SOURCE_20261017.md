# Isolated Publisher-Authored No-PRI BSD Syslog Source Fidelity (2026-10-17)

**Product/source integration is NOT authorized.** This PoC is stacked exclusively on Draft PR #50 exact HEAD `29e9d0b3999d90c1b214266d3f5e756123fbf401`. No modifications were made to the product, existing Draft PRs #29–#50, main, native Stellar, DP, sensor, deployment, release or credentials. The owner's new product UX and one-parser requirement live separately in roadmap Draft PR #51.

## What was independently pinned before candidate scoring

- Publisher-authored MIT sources: `crowdsecurity/hub@46df77d6739c41b4e808ef572188f950ba84fecd`. Four original log files **and** four separately written parser-assertion files are immutable upstream authors' materials; eight SHA-256-checked files / **123,059 bytes**. Exact metadata is in `scripts/poc/publisherCrowdsecSourceManifest.pinned.json`; original logs, publisher assertions and oracle remain private mode 0700/0600. No raw logs or field values are committed.
- The first separately frozen Python author-expected original-byte oracle SHA `e147d816e5ff88f46476d3716e6fe61b10e48852eaa99b025cc0e83ec0d07dee` included 17 physical lines and 27 partial source-name/value/byte triples. Critically, **11** asserted `message` values in vendor-origin test logs meant **raw pass-through of the entire input**, not a real source field. Counting those against a Syslog-envelope extractor is invalid.
- The qualification correction was saved separately as v2 SHA `d5f1766454bab304be4031c47ac136c88e67e6d941f6120260b52da02b3c1e0a`, retaining v1 unchanged. It excludes those 11 raw-pass-through records and preserves **4 scorable original events / 16 independently author-asserted partial Syslog source triples** (1 RFC5424 nginx-wrapped and 3 RFC3164-style PRI-less BSD messages). The remaining **13 physical lines are UNSCORABLE for this source-field contract**, including two terminal empty physical lines. The v2 correction was made **after initial v1 baseline inspection**: this evaluation is **NOT a fresh blinded holdout**. Do not include those 11 no-new-field cases in either FP or FN.
- The observed 16 triples use only the publisher-authored `s00-raw` stage expectations whose source values occur at unique exact UTF-8 offsets. Dynamic stage-derived or ambiguous assertions are excluded. Extra unasserted candidate fields cannot be scored as FP because the expected oracle is intentionally partial.

## Reusable generic improvement and measured limitation

The isolated `publisherQualifiedUnprioritizedSyslog.ts` adds **strict RFC3164/BSD TAG[PID] without a PRI prefix**, only when a publisher/transport framing assertion is explicitly supplied. It verifies bounded month/day/clock/host/TAG/PID/message boundaries, preserves exact raw bytes and UTF-8 source locations, and records unknown year/zone **without fabricating PRI, year, timezone, origin host identity or manufacturer meaning**. A missing qualification context yields **RAW_ONLY** with no new field claims. Malformed/concatenated/oversized bodies abstain. New outcomes are **REVIEW_ONLY source proposals**, never auto/native/semantic certified.

Same frozen v2 denominator (partial author-asserted fields, **not** full native event truth):

| Publisher-authored cohort | Source triples | Previous Syslog envelope exact | New qualified source exact |
| --- | ---: | ---: | ---: |
| RFC5424 with Nginx payload (one scorable original) | 4 | 4 | 4 |
| PRI-less RFC3164 syslog (three scorable originals) | 12 | 0 | 12 |
| **Total independently asserted, source-only** | **16** | **4** | **16** |

Candidate introduces **12 additional exact author-asserted name/value/UTF-8 byte triples**, no wrong same-name claims on those 16, and **0 original-byte drifts**. It is NOT an all-vendor improvement rate or evidence of a native Stellar parser, and without a complete source oracle we do **not** claim independent whole-event FP=0 or perfect parser success.

## Historical malformed REVIEW_ONLY: unchanged, not misrepresented as solved

A SHA-frozen **historical safety replay**, not a new independently scored source holdout:

- **1,361** historical original messages plus **2,892** previously generated invalid mutations (do not relabel as newly independent originals).
- The existing arbiter still emits **197** lexical `REVIEW_ONLY` proposals: **171 Sophos-shaped KV body** lexically replayed without manufacturer semantics, plus **26 envelope-only** RFC3164 suggestions without a qualified body. These are not full source/native parse success.
- With no qualified producer grammar context, the new observer makes **0 new field claims, 0 implicit source REVIEW promotions, 0 auto/native approvals and 0 byte drifts** on all 4,253 old messages. A non-profiled original cannot silently use the new PRI-less grammar.
- The historical source-gate with an independently supplied negative profile can downgrade 197/197 to ABSTAIN, but **this is not autonomous discovery of 197 malformed logs**. The 171+26 remain **UNRESOLVED** without independently expected manufacturer-level malformed/escape/framing evidence. A blind lexical heuristic to forcibly convert them to success or failure would be misleading.

## Remaining evidence gates

- All four new publisher original log files contain **no literal backslash escapes**; they **cannot certify manufacturer-specific escaped-value rules**. Manufacturer firmware/wire-mode semantics and the known Fortinet escaped-value mismatch remain **NOT_CERTIFIED**, not patched.
- The upstream assertions contain **no independently asserted empty/null source-value interpretation** on these original cases; zero-width unquoted assignments remain deliberately abstained under existing PR #50 qualified logfmt handling. Manufacturer-specific empty vs nil vs absent is **UNSCORABLE** without source-authoritative expected truth.
- This new cohort independently supports PRI-less BSD envelope field extraction, not arbitrary nested forwarder transport, overwritten source headers, dynamically user-selected prefix/postfix rules, native Stellar integration, or full mixed-vendor dispatch. Those belong to separate owner-gated product roadmap milestones and require paired original+forwarded author evidence.

## Acceptance and non-regression

- Focused RED→GREEN source replay on 3 original PRI-less BSD upstream events, plus deterministic malformed/UTF-8/unit controls.
- Full Vitest/typecheck/build/Chromium and pinned browser↔HTTP integration must run at **exact candidate HEAD** and recorded CI; local or GitHub failures remain blockers to any promotion.
- Repeat historical exact frozen safety; no change to historical 197 status, no false-complete success, no silent raw loss, and existing 50 publisher-authored CEF/LEEF/CSV partial sources retain their documented results.
