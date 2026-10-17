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
before candidate scoring. The upstream original data are Elastic publisher
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
scorable events, 1 UNSCORABLE, 590 externally asserted source name/value/
exact UTF-8 byte-location triples. Original source assertions map strict
publisher-expected ECS paths to canonical envelope token names: pri,
hostname, appname and message_id. This mapping does not certify manufacturer
native field names or Stellar normalization, and does not enumerate all
source fields.

## Frozen-identical baseline/candidate denominator

| Metric | PR #52 baseline | Qualified candidate |
| --- | ---: | ---: |
| Publisher original records | 149 | 149 |
| Partially source-scorable events | 148 | 148 |
| Author-asserted exact field triples | 590 | 590 |
| Exact TP (name/value/UTF-8 span) | 294 | 442 (+148) |
| FN on asserted triples | 296 | 148 (-148) |
| Conflicting assertions of the same expected name | 0 | 0 |
| Original UTF-8/raw drift | 0 | 0 |
| Unqualified new field claims | — | 0 |
| Automatic/native promotion | 0 | 0 |

This is a measured improvement in PARTIAL publisher-asserted source-field
recall (294/590 to 442/590), not manufacturer-universal parsing success.
The 148 additional exact assertions are bare APP tag boundaries on publisher
test inputs. All 148 remaining FNs correspond to source message_id tokens,
which require separate structural evidence before any generalized extraction.

The zero same-name conflicts do NOT establish all-field FP=0. Additional
unasserted source fields and complete-event FP cannot be scored from a
partial oracle. Manufacturer decoded values/native success are NOT_CERTIFIED.

## General structural observation, not manufacturer patching

- New observer: src/poc/publisherQualifiedBareTag.ts. No Cisco/ISE-specific
  product name matching or unbounded regex branch is introduced.
- An independently asserted PUBLISHER_ASSERTED_RFC3164_BARE_APP_TAG frame
  is required; otherwise the new observer returns RAW_ONLY with zero claims.
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
