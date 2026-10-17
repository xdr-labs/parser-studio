# Publisher-qualified bare RFC3164 APP tag: source-only accuracy (2026-10-17)

## Scope

- Exact base: PR #52 commit 492964acf36594be02a6c10f14f43dfa1c90614a.
- New branch: poc/publisher-cisco-ise-bare-syslog-20261017, isolated PoC only.
- No product/main/roadmap/dirty-WIP/native-DP/sensor/deployment/release/merge modifications.
- No automatic success, native compatibility, manufacturer escape/empty semantic claims.

## Independently frozen publisher originals and assertions

Upstream: Elastic-maintained Cisco ISE pipeline tests, elastic/integrations, exact
revision 615252c0910be1b8dc4dbe8f70acabe02ea8757e. Four original
log files and four independently authored expected JSON files were pinned
before candidate scoring. This upstream repository was used in older
PoCs for OTHER products and files; its repository identity is not new.
The four Cisco ISE fixture paths used here were absent from the prior pinned
repo manifests and baseline source/docs search. This is a new file-level
publisher cohort, NOT a genuinely unseen upstream organization nor independent
Cisco-manufacturer wire evidence. The upstream original data are Elastic publisher
test fixtures, not proven Cisco device-wire captures.

Upstream license: Elastic License 2.0 (pinned LICENSE.txt; restricted to
private evaluation, no redistribution). All 8 upstream files, LICENSE,
expected raw values and immutable oracle v1 are saved under
~/.local/state/parserstudio-elastic-cisco-ise-independent-20261017
with 0700 directory and 0600 file permissions. Git contains ONLY the
provenance/hash/denominator manifest and reproducible code, no raw material.

Immutable private oracle SHA-256:
7453879258705368c551c357fd46c0901f31e23ebee401f1bb424d006787da2c

The private oracle includes 149 physical original lines, 148 partially
scorable events, 1 UNSCORABLE, and 590 partial validation tuples. Each
tuple combines a publisher-asserted EXPECTED ECS value, an evaluator-selected
source token name, and a deterministic UTF-8 byte span derived from that
asserted value and the original raw message, independently of the candidate
parser. **The publisher did not independently author the span offsets**.
In particular, the publisher's category.name is mapped by our evaluator to
an RFC3164 bare-tag candidate called appname. That mapping is a source-locator
hypothesis, not manufacturer-certified native field identity or Stellar
normalization. This oracle is partial and cannot prove whole-event FP=0.

## Frozen-identical baseline/candidate denominator

| Metric | PR #52 baseline | Qualified candidate |
| --- | ---: | ---: |
| Publisher original records | 149 | 149 |
| Partially source-scorable events | 148 | 148 |
| Publisher-valued / evaluator-byte-located partial tuples | 590 | 590 |
| Exact TP (name/value/UTF-8 span) | 294 | 442 (+148) |
| FN on asserted triples | 296 | 148 (-148) |
| Conflicting assertions of the same expected name | 0 | 0 |
| Original UTF-8/raw drift | 0 | 0 |
| Unqualified new field claims | — | 0 |
| Automatic/native promotion | 0 | 0 |

This is a measured improvement in PARTIAL publisher-ECS-aligned source-token
recall (294/590 to 442/590) with exact byte replay, not independent device-
wire-name accuracy or manufacturer-universal parsing success.
The 148 additional matching publisher-value/byte-location tuples identify
bare APP-tag-like boundaries in the publisher's test inputs. Upstream normalized
category.name must not be mistaken for an independently certified source
field label from actual Cisco ISE firmware. All 148 remaining FNs correspond to source message_id tokens,
which require separate structural evidence before any generalized extraction.

The zero same-name conflicts do NOT establish all-field FP=0. Additional
unasserted source fields and complete-event FP cannot be scored from a
partial oracle. Manufacturer decoded values/native success are NOT_CERTIFIED.

## General structural observation, not manufacturer patching

- New observer: src/poc/publisherQualifiedBareTag.ts. No Cisco/ISE-specific
  product name matching or unbounded regex branch is introduced.
- An explicit PUBLISHER_FIXTURE_BARE_TAG_PROFILE context is required;
  without this fixture-only source profile the observer returns RAW_ONLY.
  The **entire 149-line frozen publisher source cohort** receives the profile;
  no decision to apply it is based on expected field names/values per row.
  With this cohort-level selection 148 examples remain partial REVIEW_ONLY,
  one unscorable input abstains with zero claims. No candidate success is
  promoted into a native or complete parsing verdict.
- Existing general RFC3164 framing validates PRI, clock, host, bounded bytes
  first; only an independently profiled bare APP token may then be separated
  from the raw, unmodified source message.
- Source UTF-8 replay, non-overlap, maximum 3 attempts and depth 1 are
  enforced. REVIEW_ONLY, autoPromoted=false, manufacturer semantics
  NOT_CERTIFIED and native parser NOT_VERIFIED persist.
- Invalid clocks, multiline messages, oversized events, colon-tagged
  RFC3164, RFC5424 and CEF/LEEF are negative guards on the optional
  observer. The existing engine is unchanged.

## Unresolved evidence

- 13 original lines with backslashes lack independently certified device
  decoding: escape semantics remain UNSCORABLE.
- 7 lines with syntactic empty assignments have no producer-authored
  distinction between empty, nil and absent: UNSCORABLE.
- Device-to-forwarder paired logs and nested mixed RFC3164/5424 relays
  have no independently certified source/relay roles: UNSCORABLE.
- Historical 1,361 originals + 2,892 deliberately invalid mutations are
  regression-only. Existing 197 lexical REVIEW_ONLY (171 Sophos-shaped
  KV, 26 envelope-only) remain unchanged; no autonomous FP improvement claimed.
- Previous independently pinned 50 CEF/Syslog/LEEF/CSV originals are
  verified separately as historical safety, not re-scored as new goldens.
- Native Stellar/Fluentd, DP/sensors: NOT_VERIFIED and NOT_AUTHORIZED.
- Owner product UX (named types, 10 examples/type, Union Schema,
  manufacturer CSV, draggable Prefix/Postfix and one conditional Stellar
  parser) stays roadmap-only in Draft PR #51.

## Private, reproducible validation commands

Run the following on dev-atlas in the isolated worktree; do not print
private original messages, expected values or oracle content:

    python3 scripts/poc/freezeElasticCiscoIsePublisherOracle.py
    npx --no-install tsx scripts/poc/scoreElasticCiscoIseBareTag.ts
    npx --no-install tsx scripts/poc/runBareTagHistoricalSafetyReplay.ts
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    npx vitest run src/poc/publisherQualifiedBareTag.test.ts
    npm test
    npm run build
    git diff --check

Completion requires a newly pushed Draft PR and exact candidate HEAD
GitHub Actions SUCCESS, including TypeScript/Vite, Chromium user paths,
pinned independent backend and real Chromium-to-localhost HTTP integration.
