# P0-STD-9 — Independently publisher-authored W3C source example oracle

## Source, immutability and rights protection

Publisher: W3C, *Extended Log File Format* Working Draft:
https://www.w3.org/TR/logfile/

An independently published, full example accompanies the spec. The exact
HTML bytes were fetched from the publisher, SHA256
4d05a8d6da5b574bdcc9a4aeebc2df146140ece850e239e150069d15c4206175.
The first and only <pre> block declaring #Fields: time cs-method cs-uri
was extracted; **exactly one leading HTML layout LF** was removed to
form a single source log block without an artificial blank record.
No data lines, directives, field values, encodings, quotes or physical
terminators were otherwise changed. The resulting private original
has SHA256 5f687cab7a77ce375051fdb2d24fb63812d470fb68027f776c23fe466e2797da,
172 original UTF-8 bytes, seven physical lines and four publisher
example event rows. These are illustrative standards examples and
are NOT captured commercial device/firmware wire events.

The original publisher HTML and extracted raw log are stored **only**
under private dev-atlas mode 0700 directory and mode 0600 files:
~/.local/state/parserstudio-std9-publisher-w3c-20261018/.
No publisher example source bytes or copyright-sensitive standards text
are copied into this Git repository, exposed in PR attachments or used
to train/browse customer data. A new owner can reproduce the original
from the public URL only if the publisher HTML SHA remains exactly pinned.

## Frozen independent expected truth before parser scoring

The explicit W3C publisher #Fields directive gives ordered field
identities. The independent pin builder extracts exactly the example
source, verifies the issuer/byte digest, then derives 4 rows x
3 producer-declared field claims by **original source slices, without
invoking any Parser Studio parser, scanner, scorer, or product path**.
It freezes only field names, exact UTF-8 offsets, SHA256 digests of
raw lexemes and expected decoded literals, and original document/source
SHA. No raw source-field contents are redistributed in the manifest.

- Generator: scripts/poc/freezeStd9PublisherW3cExample.py
- Frozen digest-only oracle: scripts/poc/standard9PublisherW3cExample.pinned.json
- SHA256 of frozen oracle:
  76b37af28dee2538121801320269b6152ff8199a169f458021d6d5762a5d64e5
- Source-only scorer: scripts/poc/scoreStd9PublisherW3cExample.ts
- Private original required for local scorer. If absent, the source is
  explicitly **UNSCORABLE**; it must not be silently synthesized from
  the committed expected answer or called a verified test in CI.

This is a genuine independently authored **publisher documentation
example**, but it is published and visible before development, hence
NOT a blind manufacturer holdout or proof of all supported log variants.
It is separate from the historical 1,361 originals, 2,892 mutated-invalid
and prior 50 independent source safety records.

## Measured exact field identity/value/offset evidence (dev-atlas)

Frozen-before-scoring manifest, independently fetched original and the
isolated Draft PR #65 parser were compared on the same original:
- source SHA256 matches the publisher-pinned original;
- 4/4 publisher sample rows exact under the narrow structure contract;
- 12/12 producer-declared original field names, decoded values and
  absolute original UTF-8 byte spans exact;
- TP=12 / FP=0 / FN=0 on **these twelve narrow explicit claims only**;
- original byte drift=0;
- native target NOT VERIFIED; complete security event accuracy
  UNSCORABLE, no semantic normalization or source-vs-relay clock proof.

No vendor-specific regex, fixture-driven production mapping or native
Fluentd/Stellar claims were introduced. This does not qualify P0-STD-9
for every manufacturer, protocol version or W3C/IIS variant.

## Acceptance and still-open gates

The standalone publisher-example scorer must match exact source and
oracle SHA, fail closed when the private original is unavailable,
and never claim whole-event/native success. A unit test checks only
the committed manifest's SHA/provenance without requiring or faking
private customer/publisher bytes in GitHub CI.

Full deterministic/unit/English-only, TS/Vite, Chromium user scenario,
pinned backend loopback HTTP CI, and historical source safety are
separate exact-head gates on the isolated PR. Real independently
publisher-issued device wire goldens, multiple relay hops, diverse
actual CEF/LEEF W3C/Zeek/JSON/KV formats, STD-10/11 qualification
and product release readiness remain open.

## Reproduce

    python3 scripts/poc/freezeStd9PublisherW3cExample.py
    npx --no-install vitest run src/poc/standard9PublisherW3cOraclePin.test.ts
    npx --no-install tsx scripts/poc/scoreStd9PublisherW3cExample.ts
    npm test
    npm run build
    git diff --check
