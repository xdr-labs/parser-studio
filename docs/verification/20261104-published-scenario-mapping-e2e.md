# Published Parser Studio scenario corpus — full field-mapping acceptance

Date: 2026-11-04
Product: `xdr-labs/parser-studio`, PR #206, candidate branch `fix/juniper-sd-field-normalization-20261104`
Source of truth: `xdr-labs/parser-studio-docs` main `b5e0733`, `practice/*.log`.
Scope: exact published browser inputs, source extraction, Stellar Cyber 7.0 semantic mapping, local DRAFT Ruby/.conf compilation. No production release and no Stellar DP installation.

## Evidence method

- Copied all 12 public `practice/*.log` inputs byte-for-byte into `tests/fixtures/docs-practice-20261104/`, plus the documented Snort v0.2 recipe. No synthesized replacement, trimmed error event, or modified security field value.
- Independently verified Juniper 2-event source SHA-256 `51d892ff0b8924be7f5b5e73f4c5c1c7ac8830be655d431ff9153c8bf5d4d052` against the public practice download.
- Used actual Chromium UI → same-origin pinned loopback analysis/authoring server. Checked `Add Logs → Analyze Logs → Review Fields → Map Fields`, and for eligible samples `Create Parser → DRAFT Ruby/.conf` with file SHA verification.
- Ran Snort ChatGPT Assisted with the **published source**, published `REVIEW_ONLY` recipe, and **different published holdout** events. No claim of a new independent ChatGPT response; the video recipe itself was reused.

## Browser acceptance matrix

| Documentation practice sample | Original events / recognition | Extracted field paths | Official Stellar 7.0 mappings | Vendor-only preserved | Route/outcome |
| --- | --- | ---: | ---: | ---: | --- |
| `01-juniper-srx.log` | RFC5424 CREATE + DENY, 2/2 | 41 | 6 | 35 | DRAFT Ruby/.conf PASS |
| `02-sophos-xg.log` | Two original partial/unsafe events | — | — | — | Partial/ChatGPT repair path retained |
| `03-snort-alert.log` | One unknown alert | — | — | — | Assisted recipe + separate holdout + DRAFT PASS |
| `03-snort-holdout.log` | Two independent alerts | — | — | — | Assisted holdout PASS |
| `04-fortigate-traffic.log` | Two original traffic events, 2/2 | 50 | 8 | 42 | DRAFT PASS |
| `04-fortigate-threat.log` | Two original Web Filter/IPS events, 2/2 | 42 | 8 | 34 | DRAFT PASS |
| `05-relay-original.log` | Two unwrapped traffic events, 2/2 | 50 | 8 | 42 | Mapping reviewed |
| `05-relay-forwarded.log` | Two genuine rsyslog output events, 2/2 | 50 | 8 | 42 | Declared `relay01`; DRAFT PASS |
| `05-relay-holdout-original.log` | One unwrapped Web Filter holdout | 36 | 8 | 28 | Mapping reviewed |
| `05-relay-holdout.log` | One rsyslog Web Filter holdout | 36 | 8 | 28 | Declared `relay01`; DRAFT PASS |
| `06-panos-traffic-issue.log` | One documented positional CSV issue record | 100 structural paths | 6 | 91 | DRAFT PASS; 3 internal bookkeeping paths intentionally not emitted |
| `07-elasticsearch-java-error.log` | 16 physical lines, one unconfirmed logical event | — | — | — | Multiline event-boundary review retained |

The 100 PAN-OS paths include three non-data extraction bookkeeping keys (`generic.mode`, `generic.delimiter`, and `*.source_raw`); 97 actual candidate output paths survive. Do not falsely report them as discarded security event values.

Combined FortiGate Traffic + Web Filter + IPS: 4 original events, 66 discovered paths, 7 verified official destinations, 59 vendor-only, **0 omitted**, no must-fix errors, one DRAFT parser successfully compiled. The former 60-map budget silently excluded 6 paths; updated bounded suggestion + generic-structural handoff limits are 100, with regression checks.

## Semantic correctness and fail-closed decisions

- Juniper structured `syslog_sd.element_1.params.source-address → srcip`, `destination-address → dstip`, `protocol-id → proto`, `policy-name → rule.name`; `timestamp` and `hostname` unchanged. Distinguish these **source paths** from normalized output names.
- Juniper mixed ICMP/UDP `source-port`/`destination-port` are **not** bulk promoted as Layer-4 port fields; protocol-dependent meaning needs explicit review. `nat-*`, `service-name`, missing/placeholder `username` are retained without false semantic assertions. Sparse or non-ICMP `icmp-type` not bulk promoted.
- FortiGate `policyid → fw_policy_id` is a supported documented alias. Do not promote vendor `type`, `eventtype`, `direction` or `hostname` to unrelated Stellar fields. Vendor `duration` is expressed in **seconds**, Stellar `duration` is **milliseconds**; until an explicit safe conversion is implemented, keep original value as vendor-only.
- PAN-OS Syslog PRI `severity` is not Stellar's 0–100 security severity score; PAN-OS category `type=TRAFFIC` is not Stellar's Windows-agent `type`. Keep these vendor-only. Confirmed PAN-OS source/destination IPs, Layer-4 ports, transport protocol name and action remain standard mapped.
- All other unverified vendor classifications are preserved under the manufacturer namespace, not invented Stellar dictionary names.

## Verification files and test boundaries

The exact corpus test fixtures are in `tests/fixtures/docs-practice-20261104/`. Unit tests:
`src/guided/docsPracticeSemanticMapping20261104.test.ts`,
`src/guided/docsPanosPositionalFieldSafety20261104.test.ts`,
and the updated `fieldMappingSuggestions.test.ts`.

Chromium tests:
`tests/docs-practice-inventory-20261104.spec.ts` (12 samples),
`tests/docs-practice-full-authoring-20261104.spec.ts` (6 generated DRAFT pairs),
`tests/docs-fortigate-multiple-types-20261104.spec.ts` (combined 66/66),
`tests/docs-snort-assisted-20261104.spec.ts` (reviewed recipe + independent holdout).
These tests explicitly require a pinned real local backend; they are not smoke tests against a mocked authoring service.

**Final same-candidate acceptance after both 60-to-100 cap changes:** Vitest **1,363/1,363 PASS** across **178/178 files**; TypeScript + production Vite build **PASS** (existing >500 kB bundle advisory only); actual Chromium with the pinned same-source loopback authoring backend **20/20 PASS**. Previously obsolete 60-field refusal tests were corrected to assert preservation of every source path that is now within the supported bound. The original, current, and independent holdout events were not altered.

Limits: A generated `DRAFT` pair and compiler checksum do not certify Fluentd native execution, Stellar 7.0 DP import or live log reception. No release or target apply was attempted.
