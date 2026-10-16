# Independent Public Security-Log Holdout — 790 Events (2026-10-16)

## Scope and provenance

This is a **research PoC**, isolated on `poc/syslog-envelope-foundation-20261016`. No active product worktree, deployment, release, sensor, or live Stellar Cyber DP was changed. All parser code, tests, and documentation are in English.

The test set is drawn from **29 publicly available upstream fixture files** in [Elastic Integrations](https://github.com/elastic/integrations/tree/ee918d03f4a90dacd32673546c64a633308796ef), pinned at Git commit `ee918d03f4a90dacd32673546c64a633308796ef`. File paths, byte counts, record counts, and source SHA-256 hashes are fixed in `scripts/poc/publicSecurityHoldout.manifest.json`.

No raw events are committed. The downloader writes raw events and derivatives to the owner-local, permission-restricted `~/.local/state/parserstudio-ext-holdout-20261016/` directory (0700 directory, 0600 data files). No customer events were involved.

The evaluation comprises 730 PAN-OS logs across 19 fixture families, 43 Cisco Umbrella logs across seven families, and 17 Microsoft Defender/M365 Defender JSON logs across three fixture types.

## Independent baseline and qualified candidate

| Measure | Pre-change baseline | Qualified candidate | Interpretation |
| --- | ---: | ---: | --- |
| Input events | 790 | 790 | Identical pinned source fixtures |
| Events with successful structural parsing | 448 (56.7%) | 777 (98.4%) | +329 events / +41.6 percentage points |
| Source-independent CSV oracle checks | Not independently reported for baseline | 758 / 766 exact | Full original ordered field values equal the Python `csv.reader` oracle |
| CSV field mismatch despite emitted columns | Not independently reported | 0 | No counted false structural success among all 766 oracles |
| CSV records safely left without extracted columns | Not independently reported | 8 | Rejected or partial rather than inventing values |
| Defender JSON records structurally recovered | 17 / 17 | 17 / 17 | No change required |
| Defender JSON scalar leaves retained | 675 / 675 | 675 / 675 | Includes repeated occurrences; raw-copy shortcuts excluded |
| Calendar and quoting adversarial variants | 218 false acceptances observed during candidate hardening | 0 / 1,532 accepted | Strict known PAN signature prevents loose fallback |

The first baseline on the pinned 790 fixture corpus was measured **before** any holdout-driven parser changes. The subsequent 777/790 candidate was intentionally improved against this corpus. Therefore **777/790 is a qualification result on a development/tuning corpus, not an unbiased out-of-sample generalization estimate**.

There are 24 events without an independent CSV oracle (17 JSON and seven PAN samples with no reliable standard CSV anchor), and 13 events that are not structurally parsed. Two PAN variants count as structured but are not independently certified column-by-column. A passing parse is therefore never presented as proof of complete semantic field mapping, normalization, Stellar exporter compatibility, or native parser execution.

## Root causes and corrections

1. **PAN-OS transport and source-body coupling**: Plain positional PAN-OS CSV, blank serial fields, hostless BSD timestamps, and optional dash body separators failed even though body grammar was known. The reusable envelope and body stages now handle these independently, without multiplying full-line vendor regexes.
2. **CSV dialect differences**: Cisco Umbrella exports include fully quoted fields, mixed quoted/unquoted date-based records, escaped quotes, embedded commas, and optional spaces after commas. A bounded single-record CSV tokenizer was added alongside (not in place of) the header-aware RFC 4180 block parser. Fields with no authoritative schema are retained as `column_N`.
3. **PAN-OS Audit**: The eight-column audit family differs structurally from Traffic and Threat. An explicit bounded audit leaf was added **after** common framing and prior to semantic mapping.
4. **Quote handling**: Literal double quotes inside otherwise unquoted PAN-OS values must not start an escaped CSV field. The positional tokenizer now treats quotes as structural only at the start of a field.
5. **Known-source strict failure**: An invalid date in a strong PAN-OS body signature previously could be rejected by its strict parser but accepted by a generic positional CSV fallback. `claimsPanosSignature` makes that failure terminal. This change eliminated the 218 observed malformed acceptances without reducing the original source-extraction counts.

## Adversarial controls

Each of the 766 independently identified CSV rows was subjected to two deterministic negative mutations: one impossible calendar date when a date anchor is present, and one dangling quoted field. This yields 1,532 controlled malformed records.

The acceptance gate requires `0/1532` malformed records to parse successfully. It also requires the original PAN-OS and Umbrella source fields to be preserved **exactly** (field count, order, and string value); partial extractions cannot be counted as accurate.

These mutated variants are regression and strictness controls, not a comprehensive security-fuzzing claim.

## Reproduction

From the PoC worktree:

```sh
python3 scripts/poc/fetchPublicSecurityHoldout.py
npx vite-node scripts/poc/runPublicSecurityHoldout.ts
npx vitest run src/unlabeledSecurityCsv.poc.test.ts src/hostlessSyslog.poc.test.ts src/rfc4180Csv.poc.test.ts src/syslogAdversarial.poc.test.ts
npm test
npm run typecheck
npm run build
```

`fetchPublicSecurityHoldout.py --output <private-directory>` supports an alternate raw-data location. To run offline against a previously generated corpus, use `PARSER_STUDIO_PUBLIC_HOLDOUT_DIR=<private-directory> npx vite-node scripts/poc/runPublicSecurityHoldout.ts`. Do not commit or share the raw/derived private files.

Expected qualification: 790 events, 777 structurally parsed, 766 independent CSV oracles, 758 exact, eight safe missing, **zero field mismatches**, 17 Defender JSON events with 675/675 source scalars, and 1,532/1,532 negative controls rejected.

## Product implications and remaining limitations

The foundational design remains `preamble → framing/event breaking → Syslog envelope → source grammar → source preservation → semantic mapping → normalization`. Source-dependent rules must be bounded and fail-closed. The remaining eight CSV extraction gaps and seven PAN events without a reliable positional oracle need independent classification; masked or placeholder fields should not override the higher priority of preserving actual source values.

Before adopting these PoC changes in the product branch, separately evaluate additional unseen raw logs and independently measure value preservation, field-name semantics, normalization, import/export compatibility, and actual first-time-user UI workflow. Product integration is **not authorized by this PoC's success alone**.
