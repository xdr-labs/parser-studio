# Manufacturer-Documented Empty Markers in Custom Syslog: Conservative Source PoC

## Scope and immutable baseline

- Repository: `xdr-labs/parser-studio`; isolated worktree `/home/aella/parser-studio-fortios8-empty-marker-source-poc-20261017`.
- Branch: `poc/fortios8-declared-empty-marker-20261017`, based **only** on Draft PR #52 exact HEAD `492964acf36594be02a6c10f14f43dfa1c90614a`.
- Source/accuracy PoC only. No product integration, normalization, native Stellar/Fluentd/DP, sensor, production, deployment, main, PR merge, or release.
- No changes to qualified Multi-Pass, Generic Structural or bounded multi-pass Funnel base.
- Existing Draft PRs #29–#54, product HEAD `da94aa9`, roadmap PR #51 and unrelated dirty frontend/backend worktrees stay untouched.

## Pre-candidate independent manufacturer documentation

Manufacturer official reference (FortiOS 8.0.0 custom Syslog format):
https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/779135

The manufacturer documents the exact `empty-value-indicator` custom configuration and explicitly states that configured empty fields are displayed with the selected single-character marker. Its Example 2 includes **two** sample lines as received by a Syslog server with the custom indicator set to `%`.

Author-document HTML SHA-256:
`b9ef7ca4e86f416415fa9c850fd738376f59a2808fa8f3ea289d3270a4d9bcd8`

Immutable pre-candidate independently extracted oracle SHA-256:
`24779a777bcfad3d25293e480d82f7b10d61516b377144485ef92b3feaa726b1`

The source HTML page and the two exact manufacturer-authored sample lines, plus evaluator-derived source-value byte intervals and review expectations, are held privately under
`~/.local/state/parserstudio-fortios8-empty-author-20261017` (directory mode 0700, files mode 0600). **Do not commit or redistribute copyrighted original document or original example values.** Git contains only hashes/provenance and reproducible test code. The source document was frozen before candidate scoring. The two example values and their configured meaning are authored in the same manufacturer document; there is **no separate independent device capture** or separately manufacturer-published full field oracle.

## Same frozen partial denominator

| Exact manufacturer-authored custom-template evidence | Existing source lexer | New opt-in declared empty-state review |
|---|---:|---:|
| Manufacturer-published original example lines | 2 | 2 |
| Source fields in declared template | 12 | 12 |
| Exact name/source-value lexeme/UTF-8 byte-location | 12 | 12 |
| Author-documented present-but-empty fields | 3 | 3 |
| Empty-state TP supported by source contract | **0** | **3** |
| Empty-state FN | **3 (unqualified)** | **0 (reference only)** |
| Nonempty lexical value matches | 9 | 9 |
| Unexpected empty claims on compared source fields | 0 | 0 |
| Raw byte drift or source offset drift | 0 | 0 |
| Claims without the independently declared profile | 0 | 0 |
| Auto-promotion/native verification | 0 | 0 |

**This is a narrow improvement in classifying the documented empty-value marker, NOT a field-extraction gain, vendor-general empty-value performance rate, verified device-wire parser, or full-event F1.** The baseline already located all 12 lexical fields. The measured change is three explicitly declared `PRESENT_EMPTY_DOCUMENTED` reviews instead of three unqualified literal-percent values. The observation does **not** determine whether an empty field should become a null, an empty string, or a missing normalized target field.

## Generic structural rule and bounds

The new `src/poc/declaredEmptyMarker.ts` is an opt-in source-value review layered on the existing conservative source KV/UTF-8 locator. Its generic code contains no vendor-name or firmware-specific conditional parser and requires:

1. A separately declared source schema of safe field names and exact source SHA-256; bounds on input size and field count.
2. A manufacturer documentation reference hash and an explicit unquoted single-symbol `emptyMarker` configuration. It is **not** inferred by seeing a percent sign or a vendor filename.
3. Byte-exact round-trip of all accepted original key/value source regions, including RFC3164 transport prefix offsets.
4. Literal equality to the configured *unquoted* marker; a quoted `"%"`, quoted empty value, unknown backslash escape, malformed framing, wrong source SHA, or conflicting schema cannot silently become a documented empty state.
5. Separate present/nonempty, present/documented empty, present-but-unknown and absent field handling. No fabricated absent values.
6. Bounds: 8,192 UTF-8 bytes per event, up to 64 declared source keys, no recursion (depth 1), at most two attempts. Disposition remains REVIEW_ONLY / RAW_ONLY / ABSTAIN_UNSAFE, `autoPromoted=false`, `nativeStellar=NOT_VERIFIED`.

Some other FortiOS versions, producer configurations, modes (CEF, CSV, JSON, RFC5424) and firmware-specific escaping may interpret the same characters differently. This PoC **does not** attempt universal or automatic manufacturer escape decoding.

## Independent replay and unsolved risk

The historical safety replay runs **1,361 prior original logs + 2,892 generated invalid variants**, with SHA-frozen datasets. These are old safety fixtures, not new holdout accuracy goldens. The existing 197 lexical REVIEW_ONLY proposals (171 KV + 26 envelope-only) remain unchanged; not manufacturer-certified negatives and not counted as a newly measured FP reduction. The prior independently pinned 50 CEF/Syslog/LEEF/CSV partial source examples are separately rechecked unchanged.

The manufacturer page is an authored example and configuration contract, **not authenticated FortiGate wire output or proof of the on-device configuration of a particular customer**. Full producer firmware/mode proof, vendor-escaped/backslash string decoding, independently manufacturer-provided null/empty-string/missing target typing, paired original-vs-forwarder mixed Syslog, complete-field FP, and native Stellar output remain **UNSCORABLE / NOT_CERTIFIED / NOT_VERIFIED**.

The PAN-OS official escape reference (not part of this scored cohort) separately describes CSV double-quote escaping:
https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/escape-sequences
This is transport/format-specific evidence, **not permission to impose PAN-OS CSV rules on FortiOS KV**.

## Verification

On dev-atlas in the isolated worktree (do not print original source values):

```sh
python3 scripts/poc/freezeFortios8DocumentedEmptyOracle.py
npx --no-install tsx scripts/poc/scoreFortios8DocumentedEmpty.ts
npx --no-install tsx scripts/poc/runDeclaredEmptyHistoricalSafety.ts
npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
npx --no-install vitest run src/poc/declaredEmptyMarker.test.ts
npm test
npm run build
git diff --check
```

Create an isolated evidence-only Draft PR **only after local regression passes**, then verify GitHub Actions at the exact pushed HEAD including full Vitest and English-only, TS/Vite, Chromium user scenarios, pinned independent backend, and actual Chromium-to-localhost HTTP integration. No merge or product integration even if all green.

Roadmap-only product requirements—user-named log types, up to 10 same-type samples, Union Schema, manufacturer CSV field definitions, drag-selected Prefix/Postfix and one conditional Stellar parser—remain exclusively in Draft PR #51 until separately authorized.
