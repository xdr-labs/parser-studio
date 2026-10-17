# P0-STD: Normative Log Grammar Conformance & False-Complete Audit — Initial Evidence
Date: 2026-10-18 (KST)

## Priority and exact scope

Owner-directed **highest-priority** audit (canonical roadmap P0-STD-0..11 in
Draft PR #51), NOT a vendor-by-vendor Escape loop. This initial verification
runs in a **new isolated source-only branch off Draft PR #52** exact HEAD
`492964acf36594be02a6c10f14f43dfa1c90614a`, without changing its source
tree or product/main, previous qualified PoCs, two dirty frontend/backend WIP,
Stellar native/DP/sensors, deployment or release. The qualified Multi-Pass +
Generic Structural + bounded Funnel stays intact.

**Important scope constraint:** This is a broad initial *code/surface inventory
and targeted conformance audit*, not certification that every standard
constraint, every manufacturer firmware, all Fluentd/native branches or every
format has been exhaustively proven. Coverage status is machine-readable in
`scripts/poc/standardCoverageLedger.v1.json`. The ledger has 19 risk/coverage
rows linking 43 real code paths; categories include supported limited behavior,
known possible false-complete behavior, conservative source-observer divergence,
and native/producer semantics still unverified.

## Authority and provenance (STD-0)

- Pinned 11 primary reference sources in
  `scripts/poc/normativeGrammarSources.pinned.json`, including RFC 3164,
  RFC 5424, RFC 6587, RFC 5425, ArcSight CEF Implementation Standard static
  version 26, IBM LEEF 1.0/2.0, RFC 8259, RFC 7464, RFC 4180 and
  W3C Extended Log File Format **Working Draft**, plus immutable Zeek
  upstream logging-framework defaults at commit
  `63f863c6a4d5cc95a724863ab31237c02eda0eac`.
- The latest OpenText CEF v27 portal is script-rendered; the static v26 HTML
  serves as the byte-pinned baseline. Version 27 provisions still require
  explicit reconciliation rather than an unverified claim of parity.
- The current Zeek documentation portal URL could not be retrieved; the
  primary **Zeek project source** is now pinned as a vendor-authoritative
  fallback for separator, empty/unset defaults. Writer/output-specific full
  format conformance and rotation/close cases remain STD-7 work.
- Historical RFC 3164, Informational RFC 6587 / 4180, vendor-controlled
  CEF / LEEF, and W3C Working Draft are **not all equivalent to Standards
  Track IETF RFCs**. Their exact authority is tagged in the manifest.
- Third-party standard bodies remain in a **private** dev-atlas 0700 state
  directory, each file mode 0600. Only hashes, URLs, source snippets authored
  for diagnostics, and code references are committed. No license-restricted
  manufacturer original messages or private expected values are redistributed.

## Actual code surfaces inspected

| Layer / standard | Implementation locations | Observed status (not full compliance) |
| --- | --- | --- |
| RFC 6587 / framing | `src/syslogFraming.ts`, `src/securityInputPipeline.ts` | Byte-counted and non-transparent framing with limits implemented; native parity/forwarder nesting pending |
| RFC 3164 envelope | `src/syslogEnvelope.ts`, `src/poc/generalSyslogEnvelopeSpans.ts`, `src/structuredFamilies.ts` | Multiple bounded variants; source-vs-relay attribution pending |
| RFC 5424 SD/MSG | `src/rfc5424Subset.ts`, `src/poc/rfc5424SdByteEscapes.ts` | Specific SD escaping implemented; some other source inspectors abstain; cross-path semantic parity pending |
| CEF | `src/structuredFamilies.ts`, `src/poc/independentNonJsonStructural.ts` | Browser decodes multiple standard Escape/space examples; isolated source-span observer does not verify all same literals |
| LEEF | `src/structuredFamilies.ts`, `src/poc/independentLeefSource.ts` | Browser supports xHH/0xHH/literal; isolated source inspector permits a narrower safe subset |
| RFC 8259 JSON | `src/parser.ts`, `src/jsonTextSequence.ts` | JSON parsing exists but browser can silently lose duplicate source names/precision or accept malformed decoded Unicode |
| RFC 7464 JSON seq | `src/jsonTextSequence.ts` | RS/LF and record bounds implemented; security-object-only policy intentionally narrower than general JSON-seq |
| RFC 4180 CSV | `src/rfc4180Csv.ts`, `src/parser.ts` | Quotes/embedded delimiters/empty positional fields work in the targeted cases; browser trims unquoted edge spaces contrary to strict RFC4180 data preservation |
| KV/logfmt | `src/parser.ts`, `src/poc/independentLogfmtSource.ts`, `src/poc/conservativeKvGrammar.ts` | Different explicit grammar variants; browser shortcut can report success without consuming all source text |
| W3C/Zeek | `src/genericStructural.ts`, `src/securityInputPipeline.ts` | Declared-state code present; exact coverage and Zeek reference revision still need independent validation |
| Multi-Pass/Funnel | `src/poc/grammarFunnel.ts`, `src/securityInputPipeline.ts` | Bounded candidates exist; no blind assumption that browser/source/native outputs are identical |

### Important discovery: do not reimplement existing CEF/LEEF support

The unchanged browser core `src/structuredFamilies.ts` already decoded
CEF `\\|`, `\\\\`, `\\=`, `\\n` and accepted spaces within extension
values across six standards-derived *narrow positive* cases. It also accepted
LEEF x5E, 0x5E, xa6, and default tab in four positive cases.
The narrower `src/poc/independentNonJsonStructural.ts` and
`src/poc/independentLeefSource.ts` source-byte observers abstained on
some of those values to avoid unjustified exact source claims.

Therefore it would be **false** to say the entire Parser Studio engine lacks
all CEF/LEEF escaping. The gap is evidence parity among browser decoding,
source byte reconstruction and actual native output, plus specific documented
false-complete conditions; no brand-specific regex fixes are appropriate.

## Frozen targeted conformance findings

`scripts/poc/standardGrammarCases.v1.json` was authored from normative
grammar and frozen at SHA-256
`c89685936c1a2b38840695d3de0338c824d6ba57e8e9a135214c9569d7534b1d`.
It has **23 synthetic, standard-derived examples**, NOT third-party
manufacturer-origin source goldens or a blind external holdout. Against
unmodified PR #52 browser/source code:

- **17** expected narrow source values matched; do **not** call these exact
  whole-event parsing successes.
- **1** intentionally malformed CSV sample was correctly rejected.
- **5** examples were accepted without errors despite a material loss or
  unresolved source semantics:
  1. RFC 8259 object member collision: `JSON.parse` retained last value,
     silently discarding the earlier original member.
  2. Huge JSON exponent converted to non-finite JS representation, with
     no explicit source-value fidelity review.
  3. Escaped lone Unicode surrogate accepted into a non-interoperable JS string.
  4. KV parser skipped trailing non-`key=value` data after matching some fields.
  5. Unqualified KV backslash escape remained accepted with no
     manufacturer-defined decoding contract.

The **read-only product baseline** `da94aa9177c6b652eee47768efb98a9d47df8c5e`
was separately checked for these browser-path failure modes and exhibited
the same no-error behavior, without product filesystem modification.

Additional *separate* CEF standard-required header probes exposed:
- Blank vendor field accepted with no error by browser extraction.
- Blank CEF severity accepted with no error.
- Numeric CEF severity outside 0–10 accepted without error.
All three violate the documented format-level header contract and warrant
false-complete guards. The existing browser CEF implementation is otherwise
still a real parser, not blanket nonfunctional.

A separate RFC 4180 source-fidelity probe demonstrated that the browser CSV
preview removes leading/trailing unquoted field spaces. Strict source
preservation must keep those bytes (whether later producer-specific trim is
desired belongs to an **explicit** transform). This is a cross-surface
semantic divergence, not evidence that all CSV parsing is incorrect.

## First bounded source-only remediation candidate (STD-5 / STD-7 / STD-3)

**No product or native code was modified.** Two additive isolated source
review gates were created for controlled evaluation:

- `src/poc/standardSourceCompletenessGate.ts`: bounded nested JSON token
  scanner and conservative KV consumed-region validator; catches decoded-key
  duplicate collisions, out-of-range numeric representations, invalid
  decoded Unicode, trailing unconsumed KV and unknown producer Escapes.
  Preserves raw, abstains or marks REVIEW_ONLY and prevents unverified fields
  being silently promoted; does not infer a missing manufacturer grammar.
- `src/poc/standardCefHeaderAudit.ts`: neutral CEF header source guard checks
  all 7 mandatory header tokens, UTF-8 raw-versus-decoded source spans,
  escaped pipe/backslash, version, documented severity and field size limits.
  Does **not** claim CEF Extension parsing or full event success.

In the same frozen synthetic 23-case denominator, the first gate conservatively
flagged **all 5 previously silent source-fidelity conditions**, with 0 raw
byte drift and 0 auto/native promotions. That is a **safety classification
PoC**, not a measured external vendor false-positive reduction nor a product
fix. The three additional CEF header negatives were rejected by the new
source-only CEF header guard, while unchanged browser still accepted them.
Unknown/full source-field FP and native verification remain UNSCORABLE.

The **19 risk rows** link standards → code paths → supported/unsupported
behavior → next independently scorable verification. Their severity describes
priority of proof/remediation, not 19 confirmed defects.

## Remaining STD-0..11 work (explicit unfinished gates)

1. P0-STD-1: Freeze real RFC6587/5425 transport and paired forwarded
   source/relay originals, exact physical framing bytes and recoverability.
2. P0-STD-2: Cross-validate RFC5424 SD, unknown escapes, NILVALUE, timestamp
   and multiple SD elements across browser/source/native.
3. P0-STD-3: Reconcile supported browser CEF grammar with source/raw UTF-8
   spans and actual native CEF decoder. Merge *shared standard grammar* only
   after independent externally authored positive/negative expected values,
   not a single Fortinet firmware rule.
4. P0-STD-4: Reconcile LEEF xHH/0xHH/literal source spans with the already
   capable browser decoder and IBM publisher examples.
5. P0-STD-5..7: JSON duplicates/numbers/Unicode; CSV preserved edge spaces,
   multiline/trailing width; declared KV/logfmt, W3C/Zeek state/empty semantics.
6. P0-STD-8: Run one same-input cross-format/conflict/false-complete campaign.
7. P0-STD-9: Obtain **fresh independent** standards-publisher originals and
   separately authored complete or partial expected field/value/UTF-8 spans.
   Synthetic mutations and historical 1,361 originals/2,892 invalids
   (including historical 197 REVIEW_ONLY) are regression only, never fresh
   accuracy proof; prior independently sourced 50 CEF/LEEF/CSV originals
   remain frozen safety checks.
8. P0-STD-10/11: Promote only qualified common-grammar source fixes in a new
   isolated Draft PR, complete deterministic tests, English-only, TypeScript,
   Vite, Chromium user flows, pinned independent backend and actual browser ↔
   localhost HTTP exact-head CI, then publish exact residual outstanding gaps.

Preserve source/original input exact UTF-8 byte spans, repeated names and
unparsed regions, source-vs-relay host/time and conservative ABSTAIN / PARTIAL /
REVIEW_ONLY. No automatic source-complete, manufacturer wire-certified, full
event FP=0, native Fluentd/Stellar or deployment claims.

## Reproduction (new isolated source-only worktree)

```sh
python3 scripts/poc/pinNormativeGrammarSources.py
npx --no-install tsx scripts/poc/auditStandardsCoverage.ts
npx --no-install tsx scripts/poc/scoreStandardGrammarBaseline.ts
npx --no-install tsx scripts/poc/scoreStandardFalseCompleteSafety.ts
npx --no-install vitest run src/poc/standardSourceCompletenessGate.test.ts src/poc/standardCefHeaderAudit.test.ts
npm test
npm run build
git diff --check
```

Publish under a distinct Draft PR and require **exact pushed HEAD CI SUCCESS**,
with no product/main/DP/sensor/native target/credential/production/deployment/
merge/release actions. Product roadmap MEP/F, Union Schema, manufacturer CSV,
drag-selected Prefix/Postfix and single Stellar parser remain separately
authorized future product tasks in PR #51.
