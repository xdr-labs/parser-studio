# Manufacturer-Authored FortiOS CEF Backslash-Equals Source Fidelity PoC

## Scope and preservation

New source-only isolated worktree `/home/aella/parser-studio-fortios-cef-equals-escape-poc-20261017`, branch `poc/fortios-cef-declared-equals-escape-20261017`, based **only** on qualified Draft PR #52 exact HEAD `492964acf36594be02a6c10f14f43dfa1c90614a`.

The qualified Multi-Pass, Generic Structural, and bounded Multi-Pass Funnel engine, product code, main, roadmap PR #51, prior PoCs #29–#55, dirty frontend/backend WIP, Stellar native/DP/sensors, production, credentials, deployment, releases and merge remain unchanged. This observer is **not** wired into any product parser or adapter.

## New manufacturer-authored original and expected source semantics

Official Fortinet/FortiOS 7.4.8 Log Message Reference:
https://docs.fortinet.com/document/fortigate/7.4.8/fortios-log-message-reference/807724/antivirus-log-support-for-cef

The manufacturer's own page publishes an antivirus **original FortiGate disk-format KV example** and a **CEF message intended for a Syslog server**. Its field mapping table identifies original source field `ref` as CEF extension field `FTNTFGTref`, explicitly noting that a backslash was added to escape an equals character. The original KV example supplies the expected decoded value with a literal equals character; the CEF example contains the same value as a backslash-escaped equals. These values and source locations were extracted and frozen **before inspecting the candidate output**.

Official manufacturer page HTML SHA-256:
`d4085e6f7363887a88cff469837828ecaebb6647722dbb5eef8cb82d90987a40`

Independent pre-candidate reference oracle SHA-256:
`8817ce951365fa3d6291432e3080e8845c9b10dd548070b0d5035b0a8e574d86`

All original HTML, source KV sample, CEF original bytes, decoded manufacturer-expected value and byte intervals remain private under
`~/.local/state/parserstudio-fortios-cef-document-escape-20261017` (0700 directory / 0600 data). Proprietary documentation is retained for internal evaluation only and **not committed or redistributed**. Git includes source/page SHA metadata, code/tests and this report, with no copied vendor original messages or expected values.

The two examples are **manufacturer-authored reference examples**; an independently recorded device/relay packet pair, firmware-specific customer configuration, and proof of the same physical event are **NOT_VERIFIED**. The manufacturer publishes semantic equality, but original CEF UTF-8 byte intervals are derived independently by the evaluator before candidate scoring and were not manufacturer-authored offsets.

## Frozen partial-source comparison

| Manufacturer-authoritative CEF source-value contract | Previous isolated CEF observer | New declared escape observer |
|---|---:|---:|
| Manufacturer-documented escaped extension field | 1 | 1 |
| Decoded name/value and exact original escaped-byte location | **0** | **1** |
| Field false negative under this one-field oracle | 1 | **0** |
| Original source byte drift | 0 | 0 |
| New unqualified source/semantic claims | 0 | 0 |
| Autopromotion or native parser certification | 0 | 0 |
| Full original event field precision | UNSCORABLE | UNSCORABLE |

The **only measured gain** is one manufacturer-documented CEF extension field decoded under an explicitly declared backslash-equals grammar while retaining its raw escaped source value and original byte offsets. This is **not a general manufacturer Escape accuracy percentage**, not an entire CEF event parse, and not native Stellar/Fluentd qualification. The previous generic CEF observer conservatively abstains from ambiguous extension escaping; this optional source observer does not replace it.

## Generic, bounded parser design

`src/poc/declaredCefExtensionEscape.ts` is a vendor-neutral, **explicitly profile-gated** source observer. The implementation does not contain Fortinet, FortiOS, manufacturer-specific field matching, arbitrary regex patches or automatic detection of escape meanings.

It requires a valid SHA-256 of the exact original CEF input, SHA-256 of its independent manufacturer documentation, explicit evidence for a single-record CEF transport with bounded RFC3164/CEF header fields, and an externally declared safe extension field name and `BACKSLASH_ESCAPES_EQUALS` grammar.

The parser recovers only the explicitly declared CEF field; it validates value token bounds and supports **only** `\=` as an independently documented escape. Unknown `\q`, `\n`, escaped pipes, unescaped equals, malformed headers, duplicate/ambiguous same-name source fields, multiline/multiple events, invalid UTF-8 and unqualified profile sources **abstain without source claims**. Source UTF-8 value spans are replayed from the original received bytes, not the decoded output. No source is rewritten.

Boundaries: max 8192 received bytes, one selected extension value max 2048 characters/bytes, max 16 identical documented escape occurrences, max 2 candidate attempts, depth 1. All new claims remain `REVIEW_ONLY`, `autoPromoted=false`, `nativeStellar=NOT_VERIFIED`, firmware/device original wire `NOT_VERIFIED`.

## Known unsolved evidence gaps and regression requirements

- Original manufacturer document reference: one original-disk-format value and one CEF-forwarded example, not separately authenticated same-device paired packets.
- Manufacturer firmware 7.4.8 documentation does **not** certify all 7.4.x, 8.0 or cross-vendor escape semantics; exact firmware/wire trace is absent.
- Only literal backslash-equals in an explicitly declared CEF extension is qualified. CSV doubled-quotes, arbitrary KV escapes, CEF newline/pipe/backslash and nested RFC5424 transports remain **UNSCORABLE** without author-expected originals.
- No complete-event source oracle; extra fields FP and overall recall cannot be calculated from one independently specified extension field.
- The historical 1,361 originals and 2,892 generated malformed variants are **SAFETY ONLY**; 197 previous syntactic `REVIEW_ONLY` (171 KV + 26 RFC3164 envelope) are unchanged, never counted as autonomous FP reduction. Previous 50 independent CEF/Syslog/LEEF/CSV partial source cases must remain unchanged.
- Owner product features (named log types, 10 diverse same-type examples, Union Schema, manufacturer CSV definition, manually selected Prefix/Postfix, and one conditional Stellar parser) remain **roadmap-only PR #51**, not implemented or certified here.

## Acceptance verification

Run privately on dev-atlas in the isolated worktree without printing vendor original data:

```sh
python3 scripts/poc/freezeFortiosCefManufacturerEscape.py
npx --no-install tsx scripts/poc/scoreFortiosManufacturerCefEscape.ts
npx --no-install tsx scripts/poc/runDeclaredCefHistoricalSafety.ts
npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
npx --no-install vitest run src/poc/declaredCefExtensionEscape.test.ts
npm test
npm run build
git diff --check
```

Only independently measured, nonregressing source-accuracy evidence can be recorded in an **isolated Draft PR**. Require **exact-HEAD GitHub Actions SUCCESS** with unit/language, TS/Vite build, real Chromium user scenarios, pinned independent backend build, Chromium-to-localhost HTTP integration. No deployment, product integration or merge even after CI SUCCESS.
