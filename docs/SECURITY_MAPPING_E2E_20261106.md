# Security Log Parsing and Stellar 7.0 Semantic Mapping E2E — 2026-11-06

## Scope and evidence boundary

This audit used **real Chromium** on the publicly deployed **development preview**
`https://app.parser.xdr.ooo/` at product main `c8699f8a7b72bd4673399bb6d0e97a0423c26e88`.
It inspected **Auto Parser → Analyze Logs → Review Fields → Map Fields** and generated
eight real DRAFT Ruby / .conf pairs using the authoring backend. No API responses
were mocked. No real Stellar Cyber Data Processor, sensor, production cluster,
or customer raw logs were changed. Manufacturer documentation examples are not
attested real-device captures.

Primary evidence retained on dev-atlas (not checked into Git because test
artifacts are bulky):
`/home/aella/.local/state/parserstudio-security-mapping-e2e-20261106/`.
- `run.mjs`: reproducible Chromium corpus runner (71 scenarios)
- `results.jsonl`: every scenario with source provenance/hash, parse
  classification, full official/vendor mapping rows and DRAFT result
- `summary.json`: group-level scenario and UI accounting
- `candidate-browser.mjs` and `candidate-browser-mapping.json`:
  independent 11-scenario candidate browser / real backend checks
- `candidate-full-unit.log`: 188 Vitest files / 1,426 tests PASS
- Original public rollout proof:
  `/home/aella/.local/state/parserstudio-public-rollouts/release-c8699f8-20261106/public-qa/final-verification.json`.

## Parsing results: do not confuse structural success with correctness

| Evidence set | Scenarios | Fully structurally parsed | Needs review |
|---|---:|---:|---:|
| Official manufacturer *documentation* examples | 13 | 10 | 3 |
| Published Parser Studio tutorials | 12 | 8 | 4 |
| Authored security-log simulation, including malformed controls | 46 | 26 | 20 |
| **Total** | **71** | **44** | **27** |

There were **zero browser JavaScript exceptions, zero API 5xx responses**,
and zero test-harness exceptions. Eight selected scenarios generated **eight
DRAFT Ruby/.conf pairs**, all HTTP 200, two files per pair, SHA-256 verified.
The reported 953 mapping rows are **not a semantic accuracy denominator**:
192 rows have official dictionary destinations, and 761 retain vendor-specific
values, but only the independently specified semantic oracle below is
eligible for mapping precision/recall claims.

The UI requires additional review for some Snort, Cisco FTD, Juniper,
Zeek, multi-line CSV and Elasticsearch multi-line scenarios and for deliberately
invalid CEF/LEEF/KV, XML and other negative tests. Some Zeek/W3C/CSV inputs
require explicit schema preparation; the 71-case runner intentionally did
not take those optional recovery paths. Three UI summaries expressed
"Values found in 1 of 1 log event" rather than the usual
"`N of M log events structurally parsed`" string; therefore event counts
in `summary.json` are **not an exact event-completeness denominator**.

## Confirmed semantic false positives in currently deployed preview

The 7.0.xs metadata dictionary defines:
- `action`: enforcement/response action, illustrated as allow or block;
- `duration`: **session duration in milliseconds**;
- `event_type`: **machine-learning job** event type;
- `type`: top-level type from a Windows agent;
- `severity`: a normalized security severity score, not automatically
  equivalent to an IDS signature priority.

Source: `https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm`
(pinned catalog and provenance in `src/guided/stellarMetadataCatalog.ts`).

Under the deployed main, 9 specific output mappings were accepted as official
despite conflicting with their producer meaning or unverified units:

| Source | Unsafe official mapping | Safe handling |
|---|---|---|
| FortiOS traffic `action=close` | `action` | preserve session-end verb in vendor namespace |
| FortiOS system `action=login` | `action` | preserve authentication event verb in vendor namespace |
| FortiOS VPN `action=negotiate` | `action` | preserve VPN negotiation verb in vendor namespace |
| Suricata `event_type=alert` | `event_type` | preserve producer event-family label |
| Suricata `alert.severity=2` | `severity` | preserve signature priority (do not relabel score) |
| CloudTrail `userIdentity.type=IAMUser` | `type` | preserve identity category |
| WatchGuard proxy `duration=14` | `duration` | preserve unit-unknown value |
| WatchGuard deny `duration=0` | `duration` | preserve unit-unknown value |
| WatchGuard deny `type=8` | `type` | preserve ICMP type code |

This is an **oracle of these nine labelled false positives only**, not a claim
that all other automatic mappings have manufacturer-attested semantic precision.
Correct field names and values are never sufficient when dictionary semantics
and producer semantics differ.

## Fix (development branch only)

Branch: `feat/security-e2e-semantic-guards-20261106`, based on deployed main.
Modifies only the *automatic suggestion* policy; manual explicitly reviewed
mapping and vendor source preservation remain available.

- Require recognized response/enforcement action values before proposing
  official `action` (e.g., allow, block, deny, drop, accept, quarantine).
  `close`, `login`, `negotiate`, `Detection` are no longer high-confidence.
- Do not infer ML `event_type` from security product event-family strings.
- Do not infer Windows-agent `type` from arbitrary nested / generic
  `type` properties.
- Do not infer millisecond `duration` from seconds / unqualified units;
  allow explicitly `duration_ms` and `session_duration_ms` sources.
- Keep Suricata `alert.severity` as vendor signature priority when its
  event family and signature ID identify the Suricata alert context.
- Maintain positive control candidates: source/destination IP and ports,
  traffic protocol, policy ID, actual allow/block actions, AWS WAF source IP,
  and CloudTrail event time.

The new 6-case semantic acceptance oracle **failed 6/6 before the fix** and
**passed 6/6 after the fix**. Existing two semantic test files were updated to
stop asserting that manufacturer event family equals Stellar ML event type.

## Candidate E2E and build results

Against a private loopback Vite instance of the **changed source** and the
existing healthy real authoring and Multi-Pass backends:

- **11/11 real Chromium mapping and DRAFT generation scenarios PASS**
  (Fortinet traffic, login, VPN, webfilter, IPS; Suricata; CloudTrail;
  WatchGuard proxy/deny; Okta; AWS WAF).
- **9/9 explicitly labelled unsafe official mapping placements removed.**
- **0 known-good target mappings lost** under the scenario-specific positive
  controls, and 11/11 generated pair requests returned HTTP 200 with a DRAFT.
- **1,426/1,426 frontend tests PASS** (188 files).
- TypeScript `tsc --noEmit` PASS; production `tsc -b && vite build` PASS;
  production bundle-size warning remains (not newly introduced by this change).

No native Ruby compilation/receiver or actual Stellar DP ingestion is implied
by DRAFT generation. GitHub exact-HEAD CI is a separate integration gate.
**Do not merge into main or deploy until separately authorized.**

## Other findings / future acceptance

1. **Juniper mixed ICMP + UDP:** issue #232 / PR #233 independently supplies
   a predicate-based conditional port normalization. That candidate is not
   included in public main nor in this independent fix branch. Review and
   combine both branches without losing native Ruby parity.
2. **Partial inputs are expected:** Zeek TSV, some W3C / CSV, complex multi-line
   and Snort samples need the explicit review/recovery UI workflow or
   source-format-specific additional evidence. Do not rewrite all failures
   as automatic-parsing bugs.
3. **Additional manufacturer-specific semantic coverage:** prioritize
   gold-labelled recall by eligible fields per event (rather than
   number of vendor rows promoted to official), using documented manufacturer
   meanings and cross-event holdouts. Do not invent mappings to raise the ratio.
4. **Runtime acceptance gate:** actual Stellar Cyber 7.0 DP import and
   ingestion of downloaded Ruby/.conf remain **NOT VERIFIED** and require
   separately authorized test-DP access and procedure.
