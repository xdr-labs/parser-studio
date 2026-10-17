# Independent Source-KV Qualification Gate — 2026-10-17

## Scope and evidence boundary

PoC only, isolated from product parser logic. The baseline remains the accuracy-first bounded Multi-Pass Funnel and the existing `parseSecurityInput` pipeline. This change does **not** modify the application parser, data normalization, UI, native test runner, any DP/sensor target, production environment, or main/product branches.

**Problem:** A structurally successful parser return (`ok:true`) can occur even when no independent original-source field grammar validates the event. Neither structural success nor field count alone certifies the original native key/value data. A wrong value is both a false positive and a false negative.

**PoC qualification outcomes:**

- `SOURCE_FIELD_EXACT`: a pinned SHA-matching independent original-source oracle exists; its source key names **and string values** equal the existing fixed product-contract map, the parser emitted exactly one event, and both raw fields are identical to the original. This means **exact on this source oracle**, not vendor semantics, native import or production readiness.
- `SOURCE_FIELD_MISMATCH`: independent source oracle exists but the parser's name/value map is not exact. Count missing names, wrong values and unexpected names separately; keep wrong values as FP+FN.
- `SOURCE_UNSCORABLE`: no safe independently qualified original-source grammar. This decision has precedence over `parseSecurityInput.ok`; a structural parse does not promote it.
- `ORACLE_SOURCE_DRIFT`: the original event SHA mismatches its independently pinned reference. Never score or certify the candidate.
- `PARSER_NOT_SINGLE_EVENT`: rejected input, zero output events or more than one output event when one original source record is expected.
- `RAW_NOT_PRESERVED`: the pipeline-level or event-level original string differs, even if the field values match.

Every outcome has `semanticMapping=NOT_SCORED`, `nativeParser=NOT_VERIFIED`, and `productApproval=false`. No further automatic promotion exists.

## Independent source-corpus evaluation

The read-only runner `scripts/poc/runSourceKvTrustBoundary.ts` reuses **already frozen private Python oracles** from three independently sourced cohorts. It checks all source SHA identities, frozen event and field denominators, and deduplicates across sources. No fixture raw bytes, source field names or values are output or published.

| Cohort | Scorable source originals | Source key/value fields | Exact original fields | Exact whole events | Mismatched whole events | Unscorable originals |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Previous Elastic SonicWall | 178 | 3,869 | 3,869 | 178 | 0 | 0 |
| Previous Elastic Fortinet | 7 | 291 | 290 | 6 | **1** | 0 |
| Fresh third-party Fortinet bare KV | 1,002 | 11,848 | 11,848 | 1,002 | 0 | 0 |
| Fresh third-party SonicWall original RFC3164 | 59 | 759 | 759 | 59 | 0 | **2 excluded** |
| **Aggregate evidence accounting** | **1,246** | **16,767** | **16,766** | **1,245** | **1** | **2** |

Total examined original records across these specific KV cohorts: **1,248**, of which 1,246 have a safe independent source reference. The 37 other Elastic records (22 JSON, previously independently scored in PR #33, and 15 Cisco ASA prose) are **outside this KV-only score**. On SonicWall, the two ambiguous originals were structurally accepted by the unchanged product pipeline, but remain strictly **UNSCORABLE** and contribute zero to the exact-score denominator. All scored original events retained their raw source. Aggregate TP **16,766**, FP **1**, FN **1** are bookkeeping figures, **NOT an open-world accuracy estimate**. The fresh Fortinet subset contains only two ordered original field layouts and no escaped-value records.

## Fortinet escape semantics: unresolved, no parser patch

One earlier Elastic Fortinet source original differs from the current product output on an escaped-string value. This remained one false positive and one false negative after scoring. The source-only lexical reference and the existing product decoder implement different backslash handling; the exact manufacturer's intended interpretation is **not independently established** from this fixture.

Fortinet's official FortiAnalyzer guidance documents both `fgt` and `rfc-5424` forwarding formats and a transparent forwarding mode that can preserve incoming messages. Fortinet's troubleshooting article describes extra backslash escaping introduced around FortiAnalyzer 7.2.6 for RFC 5424 interoperability. Neither statement authorizes arbitrary backslash decoding in every FortiGate body KV format, nor proves the intended semantics of the specific ambiguous source field.

References:
- Fortinet official CLI reference: https://docs.fortinet.com/document/fortianalyzer/7.6.1/cli-reference/859805/log-forward
- Fortinet official troubleshooting: https://community.fortinet.com/fortianalyzer-6/troubleshooting-tip-fortianalyzer-log-forwarding-issue-with-syslog-format-causing-parsing-errors-216136
- RFC 5424: https://www.rfc-editor.org/rfc/rfc5424

**Next qualified decision:** pin authoritative *format/version-specific* raw examples for escaped quote/backslash behaviors, define exact accepted escape grammar and fail-closed ambiguity classes, score on a separate unseen source set, then consider an additive source-parser candidate after all existing holdout/Juniper/Sophos/negative gates. Do not modify the qualified production parser or mark mismatches as successes here.

## Reproduction

From this isolated PoC branch on dev-atlas (private original/oracle files must exist with access mode 0600):

```bash
node_modules/.bin/vitest run src/poc/sourceKvTrustBoundary.test.ts
node_modules/.bin/vite-node scripts/poc/runSourceKvTrustBoundary.ts
npm run typecheck
npm test
npm run build
```

The negative controls cover missing independent Oracle despite a successful parser response; bad original SHA; wrong, missing, additional and coerced values; fixed-contract mismatches; incorrect raw retention; failed parsing; and multi-event output. Existing previously completed Draft PR #29-#33 test/evidence jobs are not repeated as separate PoCs. No raw/customer source or passwords are in the repository.
