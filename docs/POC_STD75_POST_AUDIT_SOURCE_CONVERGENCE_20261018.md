# P0-STD-10/11 — Post-audit isolated standards-source convergence

## Isolation and exact upstream evidence

Repository: xdr-labs/parser-studio, dev-atlas only.
Base: previously qualified cross-family Draft PR #68 exact HEAD
90e73aca5ed417d8c13484e70b084c3f7b1d29f9.

The six **separately qualified isolated source-stage commits** were
cherry-picked with original Git SHA provenance, in dependency order,
onto a fresh independent branch only:

1. Publisher-authored CEF documentation oracle, Draft PR #69:
   f9542b0bd3f6404de57ab68de0686c318390639a.
2. Shared CEF escaped Extension original byte grammar, Draft PR #70:
   981996fac77c881c5b382db605809ab9cccba617.
3. RFC5424 Structured Data syntax vs producer ownership abstention,
   Draft PR #71:
   07403224b8793a2098deae0794e9f7dff1583183.
4. RFC5424 v1 TIME-SECFRAC / unknown Version guard, Draft PR #72:
   b058f4f2e721251a42353ea699b82b76c510c8b9.
5. Bounded Zeek fully closed block rotation, Draft PR #73:
   b998025ad02e2f6411b6be672fabb8ddaaf6b7b9.
6. W3C Extended Log Working Draft required Version/Fields and
   physical row boundary gate, Draft PR #74:
   20b8aa7a7b1990eeb942aef1c947af6f03b0b672.

All source cherry-picks applied cleanly with **zero textual conflicts**
and without modifying any parent Draft PR. This is NOT product/main,
Native Fluentd/Stellar target, DP, sensors, credentials, production,
deployment, release or merge work. All pre-existing developer changes
are preserved (original product HEAD da94aa9, frontend 11 and backend
10 intentional dirty modifications, roadmap PR #51 untouched).

## Normative source/expected-answer traceability

Original standards/audit grammar source, function and test matrix:
scripts/poc/standardCrossFamilyEvidenceLedger.v1.json

Additional independent frozen source case origins:

- CEF official publisher-written v26 source examples and original SHA:
  scripts/poc/standard9PublisherCefExamples.pinned.json.
- CEF official escaped examples:
  scripts/poc/standardCefPublisherEscapes.pinned.json.
- RFC5424 outer SD source:
  scripts/poc/standardRfc5424OuterObserverParity.pinned.json.
- RFC5424 v1 timestamp/version original source:
  scripts/poc/standardRfc5424TimeVersion.pinned.json.
- Zeek file rotation and source field offset:
  scripts/poc/standardZeekRotationStream.pinned.json.
- W3C v1 mandatory declarations and UTF-8 field spans:
  scripts/poc/standardW3cRequiredDeclarations.pinned.json.

All stand-alone synthetic expected outputs were authored, frozen and
SHA-pinned before executing candidates; those records are NOT a blind
manufacturer device-wire holdout. W3C draft is explicitly a Working
Draft, not a final W3C Recommendation. Its Version 1.0 support and
LF/CRLF record boundaries are treated as a bounded declared-grammar
profile. Unknown future versions remain UNSCORABLE.

## Verified cross-family behavior and publisher originals

After applying all six changes in the SAME SOURCE HEAD, existing
standards and cross-format suites (20 test files / 242 tests)
PASS. This includes:

- RFC6587 byte-count record framing / RFC5424 original SD spans;
- CEF escaped header and extension values with original absolute
  byte intervals, no duplicate-key auto-map overwrite;
- LEEF declared delimiter; JSON field-loss preflight;
- RFC4180 CSV original spaces and generic KV whole-source consumption;
- W3C declared Version/Fields before rows, terminal record boundary
  and original column source bytes;
- Zeek ordered fully closed blocks and schema rotation, source bytes;
- Funnel competing KV vs CSV lexical grammar ambiguity and abstention.

Independent publisher-written **documentation illustrations** remain
private mode 0700/0600 on dev-atlas and are re-scored on this exact
composed source candidate, never redistributed in GitHub or Actions:

| Public publisher example type | Claimed original source values | Exact |
| --- | --- | --- |
| W3C Extended Log Working Draft | Four original illustrative rows / 12 field name/value/absolute byte span claims | 12/12 |
| ArcSight CEF v26 0.x/1.x | Two original illustrative Syslog+CEF records / 20 header+extension field claims | 20/20 |
| ArcSight CEF escape examples | Four original illustrative Syslog+CEF records / 39 escaped-value/original span claims | 39/39 |

Each publisher illustration category is a separate denominator. Zero
false positives/false negatives is specific ONLY to those public
source claims. These are NOT production hardware captures, blindly
unseen manufacturers, native Stellar events, nor representative
cross-vendor field F1.

## Release/source-native gates not yet qualified

- Producer-original device-wire captures across many security vendors,
  firmware/subtypes and forwarding paths with independently authored
  exact fields/value/UTF-8 byte positions.
- RFC3164/5424 source vs relay hostname/timestamp and RFC5425 TLS
  transport attribution, including source origin clock quality.
- Official CEF extension/LEEF duplicate/empty manufacturer semantics
  beyond grammar and browser source fidelity.
- W3C concatenated files require separately qualified physical
  producer/framer evidence; do not infer a new W3C file simply from a
  repeated #Version after rows. Zeek source-stage rotation is not
  Native product support.
- Unknown vendor escape profile policy, user-marked CSV field names,
  prefix/postfix selection, Stellar Dictionary mapping and export.
- Native Fluentd/Stellar parser artifact compilation/behavior,
  real browser Full User E2E, exact producer field FP/FN,
  owner acceptance, Product/main/DP/sensor/production release.

All unqualified field producer semantics and native target outcomes
remain PARTIAL, REVIEW_ONLY or UNSCORABLE; no false complete promotion
or manual performance claims are allowed.

## Reproducible source-stage gate

    npx --no-install vitest run src/poc/standardCrossFamilyConvergence.test.ts src/poc/standardCrossFamilyEvidenceLedger.test.ts
    npm test
    npm run build
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    # Only on dev-atlas, privately pinned publisher source present:
    npx --no-install tsx scripts/poc/scoreStd9PublisherW3cExample.ts
    npx --no-install tsx scripts/poc/scoreStd9PublisherCefExamples.ts
    npx --no-install tsx scripts/poc/scoreStdCefPublisherEscapes.ts
    git diff --check

Full regression, safety replay and exact-head GitHub Actions must be
observed before this candidate's CI qualification; all previous known
historical 1,361 original and 2,892 mutated invalid (197 REVIEW_ONLY)
plus 50 independent old records are SAFETY ONLY, not new accuracy.
