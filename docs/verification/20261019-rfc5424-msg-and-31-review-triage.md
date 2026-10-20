# 2026-10-19 — Existing 31 review cases: structural triage and RFC 5424 MSG repair

## Source and scope

Previously completed public Chromium: 134/134 PASS, without restarting or
replaying this acceptance. Among its 100 test-authored security scenarios, the
public UI reported **69 fully complete user-facing flows / 31 review cases**.
These are authored synthetic fixtures, NOT manufacturer original oracles.
The deployed development beta is unchanged at b777d743be66.

The exact same 100 source fixtures were loaded from existing checked-in E2E
source lists, without running any browser, and compared offline using the
actual Python preview_batch interface. That source-only evaluation produced
70 SOURCE_PARSED / 30 review at baseline (114 framed events), differing from
the public UI 69/31 because one LEEF source is fully extracted but its
downstream parser compiler/review is correctly not ready. These metrics
must not be conflated.

## All 31 browser review cases, grouped by safety/root cause

| Authored synthetic scenario | Root-cause decision | Baseline Python -> candidate Python |
| --- | --- | --- |
| 46 Generic RFC5424 SD | RFC 5424 standard free-form MSG — fixed | REVIEW -> SOURCE_PARSED |
| 05 ModSecurity audit-style | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| 09 Cisco ASA message ID | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| 10 Cisco FTD threat | Textual/security-body residual — still needs source-backed review | SOURCE_PARSED -> SOURCE_PARSED |
| 11 Juniper SRX RT_FLOW | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| 12 WatchGuard Firebox | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| 19 Snort alert syslog | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| Earlier: Juniper SRX syslog | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| Earlier: WatchGuard Firebox syslog | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| Expanded: Cisco FTD intrusion | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| Expanded: Snort fast alert | Textual/security-body residual — still needs source-backed review | REVIEW -> REVIEW |
| 26 Zeek conn TSV with headers | Correct DRAFT abstention — original schema/multiline stream | REVIEW -> REVIEW |
| 47 W3C IIS WAF access | Correct DRAFT abstention — original schema/multiline stream | REVIEW -> REVIEW |
| Earlier: Quoted multiline CSV | Correct DRAFT abstention — original schema/multiline stream | REVIEW -> REVIEW |
| Earlier: Zeek TSV with schema header | Correct DRAFT abstention — original schema/multiline stream | REVIEW -> REVIEW |
| Expanded: Quoted multiline CSV | Correct DRAFT abstention — original schema/multiline stream | REVIEW -> REVIEW |
| Expanded: W3C with header | Correct DRAFT abstention — original schema/multiline stream | REVIEW -> REVIEW |
| Expanded: Zeek with tabs | Correct DRAFT abstention — original schema/multiline stream | REVIEW -> REVIEW |
| 31 Cisco Umbrella DNS | Undeclared CSV/TSV positions — user schema required | REVIEW -> REVIEW |
| 33 Zscaler ZIA proxy | Undeclared CSV/TSV positions — user schema required | REVIEW -> REVIEW |
| 48 CSV quoted delimiter | Undeclared CSV/TSV positions — user schema required | REVIEW -> REVIEW |
| Expanded: CSV unlabelled positions | Undeclared CSV/TSV positions — user schema required | REVIEW -> REVIEW |
| 49 Unclosed CSV quote | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| 50 Windows Event XML unsupported | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| Earlier: Windows Security Event XML | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| Expanded: CEF + syslog with bad PRI | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| Expanded: Malformed CEF escape | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| Expanded: Malformed LEEF header | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| Expanded: unclosed KV quoted field | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| Expanded: unrecognized plain text | Correct abstention — invalid/unknown/unsupported grammar | REVIEW -> REVIEW |
| Expanded: Zscaler NSS LEEF | Fully source decoded LEEF; native/authoring review still required | SOURCE_PARSED -> SOURCE_PARSED |

## Standards-grounded, shared engine fix

RFC 5424 section 6.4 defines an optional free-form MSG, either MSG-ANY
or BOM-prefixed MSG-UTF8. The integrated parser previously recognized the
strict header and structured-data fields, then called the KV/JSON/CSV-only
body decoder. A syntactically valid textual MSG was incorrectly returned as
NO_SUPPORTED_GRAMMAR and its original text left in the residual ledger.

The new source-grammar branch captures this exact MSG as a literal
body.message value and UTF-8 byte span after strict RFC 5424 header/SD
validation and ONLY when the existing body parser recognizes no grammar.
BOM is covered as syntax. Real embedded KV/CEF/LEEF/CSV candidates are not
silently replaced by a generic text field. Physical line controls, malformed
SD, unclosed quoted KV and invalid PRI remain fail-closed. The source syntax
is explicitly marked SYSLOG_RFC5424+RFC5424_MSG; NO device semantics,
Fluentd native compatibility or proprietary target import are certified.

Reference: https://www.rfc-editor.org/rfc/rfc5424.html#section-6.4

## Frozen 100-case, 114-event offline source comparison

| Metric | Previous b777 | New isolated candidate |
| --- | ---: | ---: |
| Authored synthetic input fixtures | 100 | 100 |
| Original logical event count | 114 | 114 |
| SOURCE_PARSED fixtures | 70 | 71 |
| Remaining source REVIEW fixtures | 30 | 29 |
| Source SHA-256 identities changed | 0 | 0 |
| Changed classifications | — | one RFC 5424 MSG fixture |
| Native Fluentd or Stellar DP verified | No | No |

The 31 original user-facing review cases have NOT been relabeled as 30
public browser cases: public b777 is unchanged, and later isolated Chromium
checks concern only the modified source grammar and fail-closed paths.

## Focused exact-candidate local Chromium confirmation

A dedicated real Chromium process connected to the candidate's Python
Multi-Pass, private offline authoring backend and isolated Vite UI on
127.0.0.1; it did not mock API responses or touch the public beta.
**3/3 PASS**, covering standards-valid RFC5424 plain MSG and BOM-prefixed
UTF-8 MSG with exact raw-byte provenance plus malformed quoted-KV rejection.

The browser correctly says **Values found** and still requires a reviewed
parser rule for these free-form MSG bodies. The standalone Python source
decoder reports SOURCE_PARSED, but this **does not** mean there is a native
downloadable Fluentd or proprietary target parser for this message shape.
The initial assertion expecting a full beginner authoring completion was
corrected to protect this distinction; full browse regression was not rerun.

The isolated browser test source uses a non-default .isolated.ts extension
to avoid contaminating the separately pinned evergreen *.spec.ts suite.
Dedicated exact-head CI steps exercise the focused Python and real-browser
tests on the same checkout.

## Next work and boundaries

Run candidate-local Chromium on a private loopback Web+Python+authoring
backend, new byte-exact deterministic tests and affected regression.
Then commit, push and verify exact-HEAD CI. Preserve Draft PR #100–#107,
all other intentionally dirty worktrees, public development beta,
Exporter and rollback. Do not merge, restart public services, deploy,
touch credentials, run target-native imports, or deliver to DP/sensors.

The remaining textual security variants need independent proof before
promoting specific field meanings; CSV positions require explicit schema,
W3C/Zeek native compiler support is not asserted, unsupported XML and
malformed sources remain user-reviewable.
