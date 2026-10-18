# P0-STD-9 — Official ArcSight CEF publisher examples, source-byte oracle

## Authority, provenance and non-redistribution

Publisher: Micro Focus / ArcSight, Common Event Format Implementation Standard,
version 26, official Web documentation:
https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm

Immutable HTML publisher source SHA-256:
e5403a0362d8534af933c3038d15c4b847c70d9fab75a282f91097e27489a994.

The source's **CEF 0.x and CEF 1.x** version examples are two separate,
publisher-written, one-line illustrative Syslog+CEF records. Their exact
original visible-text lines were extracted only after their corresponding
headings, without reformatting message characters. The HTML has additional
CEF illustration entries; these were intentionally excluded to keep the
source selection independently justified and bounded.

Private original source bytes are stored only on dev-atlas:
~/.local/state/parserstudio-std9-publisher-cef-leef-20261018/
with a 0700 directory and two mode-0600 files. Neither originals nor
publisher-protected HTML appear in repository, CI output or PR attachments.

- Publisher example 0 original SHA-256:
  1c2e9c28f971903e292ee903b41bc2f3ce7655c743b1a73cfeebb7e8b0822ca3
- Publisher example 1 original SHA-256:
  d28e4e7bef1393c00d278a8bf01842c478685d7585ab5df26e9abf52e9740ba5
- Each original is 120 bytes, including a Syslog date/host preamble
  immediately before the CEF token.
- Neither is a confidential customer capture or a production device
  packet/wire record. They are publisher-visible **illustrations**, not
  blind/unseen manufacturer firmware holdouts.

## Independent pre-frozen ground truth

Generator: scripts/poc/freezeStd9PublisherCefExamples.py
Committed digest-only oracle:
scripts/poc/standard9PublisherCefExamples.pinned.json

Committed oracle SHA-256:
c4384572021d05515f7a92918c4f00618eb0acf3e15637172be0adceaa4b4882

The independently authored generator uses the publisher text and its
seven mandated CEF header names, together with the producer-displayed
three extension keys. It computes the original raw UTF-8 source offsets
and SHA-256 digests of expected field values **before candidate parser
execution**. It never calls Parser Studio parsers while deriving
ground truth. The manifest contains only names, ordinals, raw/decoded
value hashes, byte intervals, original message hashes and source
provenance. It does not redistribute publisher message values.

## Scored on unchanged combined source grammar

Source-only scorer: scripts/poc/scoreStd9PublisherCefExamples.ts.
Static CI-safe oracle manifest test:
src/poc/standard9PublisherCefOraclePin.test.ts.

The scorer requires the exact publisher original from private dev-atlas
files; absent source means UNSCORABLE rather than fabricated results.
For each original, the scorer compares *independent* frozen fields and
absolute original byte locations against:

1. Source observer arbitrateIndependentNonJson, including the Syslog
   date/hostname envelope and ten original CEF header/extension byte
   intervals (all original byte slices replayed);
2. Browser CEF grammar extractStructuredFamily on the source-delimited
   CEF body, for original value fidelity;
3. The generic security-input pipeline on the **complete original
   Syslog-prefixed record**, checking one physical event and the
   original CEF header/extension field values.

Local exact source-only result (on this isolated tree):
- published example records 2/2 accepted, exactly one event each;
- producer-declared field identities, values and original source
  UTF-8 byte offsets **20/20 exact**;
- TP=20, FP=0, FN=0 *on these narrow 20 declared field claims only*;
- source-byte drift 0; pipeline complete-original source 2/2;
- source observer remains REVIEW_ONLY_STRUCTURED_BODY, never auto
  promoted or native-certified.

These results do **not** establish complete native Fluentd/Stellar
normalization, true manufacturer device-wire semantics or field F1
outside the two public sample messages. No vendor-specific parser
regex or firmware exceptions were added.

## Safety and remaining qualifications

The original 1,361 historical and 2,892 mutation-invalid records,
197 previous REVIEW_ONLY, and prior independent 50 examples remain
regression-only. The W3C publisher example (4 records, 12 claims)
is a *separate* public-standards sample and not relabeled here.
Official IBM LEEF documentation was inspected through the
already pinned standard source; a fresh direct original HTML request
returned HTTP 403, therefore NO IBM raw-publisher-byte ground truth
was fabricated or certified in this PoC.

Live publisher device/firmware captures, multiple relay chains,
CEF unknown escapes, malformed extensions, true timestamp/hostname
provenance, independent held-out manufacturer FP/FN and native
Stellar target remain NOT VERIFIED and require separate evidence.

Isolated PoC base is qualified Draft PR #68 exact
90e73aca5ed417d8c13484e70b084c3f7b1d29f9. Product HEAD
da94aa9, main, Draft PRs #51..68, intentional frontend/backend dirty
trees, DP, sensors, release, deployment and merge are untouched.

## Reproduction

    python3 scripts/poc/freezeStd9PublisherCefExamples.py
    npx --no-install vitest run src/poc/standard9PublisherCefOraclePin.test.ts
    # Only on dev-atlas with already frozen private originals:
    npx --no-install tsx scripts/poc/scoreStd9PublisherCefExamples.ts
    npm test
    npm run build
    git diff --check

Require Draft PR exact-HEAD GitHub CI before closure. CI must check
only SHA/manifest and deterministic parser tests; private original
is never copied to hosted actions.
